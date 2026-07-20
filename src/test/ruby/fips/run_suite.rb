require 'json'
require 'set'
require 'test/unit'
require 'test/unit/testresult'
require 'test/unit/testsuite'

require File.expand_path('../test_helper', __dir__)
require File.expand_path('fips_skips', __dir__)

$fips_harness_findings ||= []

def fips_json_string(value)
  value.to_s.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
end

def fips_error_summary(suite, message)
  {
    'suite' => suite,
    'ran' => 0,
    'passed' => 0,
    'failed' => 1,
    'skipped' => 0,
    'assertions' => 0,
    'failures' => fips_json_string(message),
    'failure_count' => 1,
    'known_drop_skips' => '',
    'artifact_skips' => '',
    'native_omissions' => '',
    'known_drop_skips_count' => 0,
    'artifact_skips_count' => 0,
    'native_omissions_count' => 0,
    'harness_findings' => $fips_harness_findings.map { |f| fips_json_string(f) }.join("\n"),
    'load_error' => true
  }
end

def fips_emit_summary(summary)
  $fips_ruby_result = summary.to_json
  puts "FIPS_RUBY_RESULT:#{summary.to_json}"
end

def fips_categorize_omission(message)
  return :known_drop if defined?(FipsTestSkips) && FipsTestSkips.known_drop?(message)
  return :hybrid if defined?(FipsTestSkips) && FipsTestSkips.hybrid?(message)
  return :artifact if defined?(FipsTestSkips) && FipsTestSkips.artifact?(message)
  return :native if defined?(FipsTestSkips) && FipsTestSkips.native?(message)

  :unexpected
end

root = File.expand_path('../../../..', __dir__)
suite_name = ENV.fetch('FIPS_RUBY_SUITE')
files = ENV.fetch('FIPS_RUBY_FILES', '').split(File::PATH_SEPARATOR).reject(&:empty?)

if files.empty?
  fips_emit_summary(fips_error_summary(suite_name, 'FIPS_RUBY_FILES is empty'))
  return
end

loaded_classes = []
begin
  files.each do |file|
    path = File.expand_path(file, root)
    unless File.file?(path)
      raise LoadError, "suite file not found: #{file}"
    end
    before = ObjectSpace.each_object(Class).select { |c| c < Test::Unit::TestCase }.to_set
    load path
    after = ObjectSpace.each_object(Class).select { |c| c < Test::Unit::TestCase }.to_set
    loaded_classes.concat((after - before).to_a)
  end
rescue Exception => e
  fips_emit_summary(fips_error_summary(suite_name, "load/setup error: #{e.class}: #{e.message}"))
  return
end
loaded_classes.uniq!

loaded_test_keys = loaded_classes.flat_map do |klass|
  klass.instance_methods(false).grep(/\Atest_/) do |method|
    "#{klass.name}##{method}"
  end
end.uniq

if loaded_classes.empty?
  fips_emit_summary(fips_error_summary(suite_name, 'no Test::Unit::TestCase subclasses loaded'))
  return
end

test_suite = Test::Unit::TestSuite.new
loaded_classes.each { |klass| test_suite << klass.suite }

result = Test::Unit::TestResult.new
begin
  test_suite.run(result) { |*_| }
rescue Exception => e
  fips_emit_summary(fips_error_summary(suite_name, "suite run error: #{e.class}: #{e.message}"))
  return
end

omissions = if result.respond_to?(:omissions)
              result.omissions
            else
              []
            end

known_drop_skips = []
hybrid_skips = []
artifact_skips = []
native_omissions = []
unexpected_omissions = []
omissions.each do |o|
  entry = fips_json_string("#{o.message} [#{o.test_name}]")
  case fips_categorize_omission(o.message)
  when :known_drop
    known_drop_skips << entry
  when :hybrid
    hybrid_skips << entry
  when :artifact
    artifact_skips << entry
  when :native
    native_omissions << entry
  else
    unexpected_omissions << entry
  end
end

failures = result.failures.map { |f| fips_json_string(f) }
errors = result.errors.map { |e| fips_json_string(e) }
enforcement_failures = []

if defined?(FipsTestSkips)
  begin
    FipsTestSkips.run_native_probes!(native_omissions)
    FipsTestSkips.audit_harness_results!(
      known_drop: known_drop_skips,
      hybrid: hybrid_skips,
      artifact: artifact_skips,
      native: native_omissions,
      loaded_test_keys: loaded_test_keys
    )
  rescue Exception => e
    enforcement_failures << fips_json_string("FIPS skip enforcement: #{e.class}: #{e.message}")
  end
end

unless unexpected_omissions.empty?
  enforcement_failures << fips_json_string(
    "unexpected FIPS omissions: #{unexpected_omissions.join('; ')}"
  )
end

all_failures = failures + errors + enforcement_failures
failure_count = result.failure_count + result.error_count + enforcement_failures.size
reported_known_drop_skips = known_drop_skips + hybrid_skips

summary = {
  'suite' => suite_name,
  'ran' => result.run_count,
  'passed' => result.run_count - failure_count - omissions.size,
  'failed' => failure_count,
  'skipped' => omissions.size,
  'known_drop_skips_count' => reported_known_drop_skips.size,
  'artifact_skips_count' => artifact_skips.size,
  'native_omissions_count' => native_omissions.size,
  'assertions' => result.assertion_count,
  'failure_count' => failure_count,
  'failures' => all_failures.join("\n"),
  'known_drop_skips' => reported_known_drop_skips.join("\n"),
  'artifact_skips' => artifact_skips.join("\n"),
  'native_omissions' => native_omissions.join("\n"),
  'harness_findings' => $fips_harness_findings.map { |f| fips_json_string(f) }.join("\n"),
  'load_error' => false
}

fips_emit_summary(summary)
