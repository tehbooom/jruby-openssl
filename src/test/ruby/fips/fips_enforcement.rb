# FIPS skip-honesty enforcement: binds category, label prefix, probe direction,
# and measured behavior so label/category/assertion mutations fail at runtime.

module FipsSkipEnforcement
  extend self

  CATEGORY_PREFIXES = {
    drop: 'DROP:',
    hybrid: 'HYBRID-GATED:',
  }.freeze

  DIRECTIONS = %i[reject success environment].freeze

  SkipEntry = Struct.new(:key, :category, :label, :direction, :probe, keyword_init: true) do
    def validate!
      unless %i[drop hybrid artifact native].include?(category)
        raise ArgumentError, "invalid skip category #{category.inspect} for #{key}"
      end
      if CATEGORY_PREFIXES.key?(category)
        expected_prefix = CATEGORY_PREFIXES[category]
        unless label.start_with?(expected_prefix)
          raise ArgumentError,
                "#{key}: #{category} entry label must start with #{expected_prefix.inspect}, got #{label.inspect}"
        end
      end
      unless DIRECTIONS.include?(direction)
        raise ArgumentError, "#{key}: invalid probe direction #{direction.inspect}"
      end
      case category
      when :drop
        raise ArgumentError, "#{key}: DROP entry must use :reject probe direction" unless direction == :reject
      when :hybrid
        raise ArgumentError, "#{key}: HYBRID entry must use :success probe direction" unless direction == :success
      when :artifact, :native
        raise ArgumentError, "#{key}: #{category} entry must use :environment probe direction" unless direction == :environment
      end
      raise ArgumentError, "#{key}: missing probe" unless probe
    end
  end

  class ProbeContext
    attr_reader :rejection_observed

    def initialize
      @rejection_observed = false
    end

    def assert(condition, message = nil)
      raise message || 'assertion failed' unless condition
    end

    def assert_equal(expected, actual, message = nil)
      return if expected == actual
      raise message || "expected: #{expected.inspect}, got: #{actual.inspect}"
    end

    def assert_match(pattern, actual, message = nil)
      return if actual.to_s.match?(pattern)
      raise message || "expected #{actual.inspect} to match #{pattern.inspect}"
    end

    def assert_nil(actual, message = nil)
      return if actual.nil?
      raise message || "expected nil, got: #{actual.inspect}"
    end

    def assert_raise(*args)
      message = args.last.is_a?(String) ? args.pop : nil
      exceptions = args
      raised = nil
      begin
        yield
      rescue Exception => e
        raised = e
      end
      unless raised
        raise message || 'expected exception but none was raised'
      end
      unless exceptions.any? { |ex| raised.is_a?(ex) || raised.class.name == ex.to_s }
        raise message || "expected #{exceptions.inspect}, got #{raised.class}: #{raised.message}"
      end
      @rejection_observed = true
      raised
    end

    def flunk(message = 'flunked')
      raise message
    end
  end

  def build_registry(entries)
    entries.each do |entry|
      entry.validate!
      entry.instance_variable_set(:@binding_fingerprint, entry_binding_fingerprint(entry))
    end
    registry = entries.each_with_object({}) { |entry, map| map[entry.key] = entry.freeze }.freeze
    validate_registry_integrity!(registry)
    registry
  end

  def validate_registry_integrity!(registry)
    keys = registry.keys
    raise 'duplicate FIPS skip keys' unless keys.length == keys.uniq.length

    registry.each_value do |entry|
      fingerprint = entry_binding_fingerprint(entry)
      stored = entry.instance_variable_get(:@binding_fingerprint)
      unless stored == fingerprint
        raise "FIPS skip binding mismatch for #{entry.key}: stored #{stored.inspect}, current #{fingerprint}"
      end
    end
  end

  def entry_binding_fingerprint(entry)
    [entry.category, entry.label, entry.direction].hash
  end

  def execute_probe!(test_case, entry)
    probe_case = test_case.is_a?(ProbeContext) ? test_case : ProbeContext.new
    case entry.direction
    when :reject
      entry.probe.call(probe_case)
      unless probe_case.rejection_observed
        raise "#{entry.category} probe for #{entry.key} completed without observing a rejection"
      end
    when :success
      entry.probe.call(probe_case)
      if probe_case.rejection_observed
        raise "success probe for #{entry.key} observed a rejection (behavior contradicts :success direction)"
      end
    when :environment
      entry.probe.call(probe_case)
    else
      raise "unknown probe direction for #{entry.key}: #{entry.direction}"
    end
  rescue Exception => e
    raise "#{entry.category} probe failed for #{entry.key}: #{e.class}: #{e.message}"
  end

  def category_for_message(message, registry)
    entry = registry.values.find { |candidate| candidate.label == message }
    entry&.category
  end

  def entry_for_omission(test_name, message, registry)
    key = omission_key(test_name)
    entry = registry[key]
    return entry if entry && entry.label == message

    registry.values.find { |candidate| candidate.label == message }
  end

  def omission_key(test_name)
    name = test_name.to_s
    if name =~ /\A(.+)\((.+)\)\z/
      "#{::Regexp.last_match(2)}##{::Regexp.last_match(1)}"
    elsif name.include?('#')
      name
    else
      name
    end
  end

  def validate_harness_omission!(test_name, message, registry, bucket)
    entry = entry_for_omission(test_name, message, registry)
    unless entry
      raise "unexpected FIPS #{bucket} omission: #{test_name} => #{message.inspect}"
    end
    unless entry.label == message
      raise "FIPS skip label mismatch for #{entry.key}: expected #{entry.label.inspect}, got #{message.inspect}"
    end
    unless entry.category == expected_category_for_bucket(bucket)
      raise "FIPS skip category mismatch for #{entry.key}: registry #{entry.category}, bucket #{bucket}"
    end
    entry
  end

  def expected_category_for_bucket(bucket)
    case bucket
    when :known_drop then :drop
    when :hybrid then :hybrid
    when :artifact then :artifact
    when :native then :native
    else
      raise ArgumentError, "unknown omission bucket #{bucket.inspect}"
    end
  end

  def audit_post_run!(known_drop:, hybrid:, artifact:, native:, registry:, runner_registry:, loaded_test_keys: nil)
    findings = []
    probe_case = ProbeContext.new

    known_drop.each { |line| audit_omission_line!(line, :known_drop, registry, runner_registry, findings) }
    hybrid.each { |line| audit_omission_line!(line, :hybrid, registry, runner_registry, findings) }
    artifact.each { |line| audit_omission_line!(line, :artifact, registry, runner_registry, findings) }
    native.each { |line| audit_omission_line!(line, :native, registry, runner_registry, findings) }

    in_scope_runner = if loaded_test_keys
                        runner_registry.select { |key, _| loaded_test_keys.include?(key) }
                      else
                        runner_registry
                      end
    expected_runner = in_scope_runner.keys.sort
    actual_runner = (known_drop + hybrid + artifact).map { |line| parse_omission(line)[:key] }.sort
    missing_runner = expected_runner - actual_runner
    findings << "missing expected runner skips: #{missing_runner.join(', ')}" unless missing_runner.empty?
    unknown_runner = actual_runner - expected_runner
    findings << "unknown runner skips in suite results: #{unknown_runner.join(', ')}" unless unknown_runner.empty?

    in_scope_native = if loaded_test_keys
                          registry.values.select { |entry| entry.category == :native && loaded_test_keys.include?(entry.key) }
                        else
                          registry.values.select { |entry| entry.category == :native }
                        end
    expected_native = in_scope_native.map(&:key).sort
    actual_native = native.map { |line| parse_omission(line)[:key] }.sort
    missing_native = expected_native - actual_native
    findings << "missing expected native omissions: #{missing_native.join(', ')}" unless missing_native.empty?
    unexpected_native = actual_native - expected_native
    findings << "unexpected native omissions: #{unexpected_native.join(', ')}" unless unexpected_native.empty?

    actual_runner.each do |key|
      next unless in_scope_runner.key?(key)
      entry = runner_registry[key]
      begin
        verify_entry_binding!(entry)
        execute_probe!(probe_case, entry)
      rescue Exception => e
        findings << "post-run probe failed for #{key}: #{e.message}"
      end
    end

    native.each do |line|
      parsed = parse_omission(line)
      entry = validate_harness_omission!(parsed[:test_name], parsed[:message], registry, :native)
      next if loaded_test_keys && !loaded_test_keys.include?(entry.key)
      begin
        verify_entry_binding!(entry)
        execute_probe!(probe_case, entry)
      rescue Exception => e
        findings << "post-run native probe failed for #{entry.key}: #{e.message}"
      end
    end

    raise findings.join("\n") unless findings.empty?
    true
  end

  def verify_entry_binding!(entry)
    stored = entry.instance_variable_get(:@binding_fingerprint)
    unless stored
      raise "FIPS skip binding fingerprint missing for #{entry.key}"
    end
    current = entry_binding_fingerprint(entry)
    return if stored == current

    raise "FIPS skip binding mismatch for #{entry.key}: stored #{stored.inspect}, current #{current.inspect}"
  end

  def audit_omission_line!(line, bucket, registry, runner_registry, findings)
    parsed = parse_omission(line)
    entry = validate_harness_omission!(parsed[:test_name], parsed[:message], registry, bucket)
    if runner_registry.key?(entry.key) && bucket != :native
      runner_entry = runner_registry[entry.key]
      if runner_entry.label != entry.label
        findings << "runner/registry label mismatch for #{entry.key}"
      end
      if runner_entry.category != entry.category
        findings << "runner/registry category mismatch for #{entry.key}"
      end
    end
  rescue Exception => e
    findings << e.message
  end

  def parse_omission(line)
    if line =~ /\A(.+) \[(.+)\]\z/m
      test_name = ::Regexp.last_match(2)
      { message: ::Regexp.last_match(1), test_name: test_name, key: omission_key(test_name) }
    else
      raise "invalid omission format: #{line.inspect}"
    end
  end
end
