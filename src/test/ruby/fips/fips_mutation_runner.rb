# Invoked from FipsSkipEnforcementTest against throwaway copies in a temp directory.
# Raises on success (mutation did not fail); exits normally when enforcement correctly reds.

fips_dir = $mutation_fips_dir
mutation = $mutation_name

Object.send(:remove_const, :FipsSkipEnforcement) if defined?(FipsSkipEnforcement)
Object.send(:remove_const, :FipsTestSkips) if defined?(FipsTestSkips)
require File.join(fips_dir, 'fips_enforcement')
require File.join(fips_dir, 'fips_skips')

case mutation
when 'drop_to_hybrid'
  entry = FipsTestSkips::REGISTRY['TestCipher#test_cipher_extended_support']
  FipsSkipEnforcement.execute_probe!(FipsSkipEnforcement::ProbeContext.new, entry)
  raise 'coherent DROP->HYBRID mutation should have failed at probe execution'
when 'hybrid_to_drop'
  entry = FipsTestSkips::REGISTRY['TestX509Request#test_sign_and_verify_rsa_md5']
  FipsSkipEnforcement.execute_probe!(FipsSkipEnforcement::ProbeContext.new, entry)
  raise 'coherent HYBRID->DROP mutation should have failed at probe execution'
when 'bogus_skip'
  unless FipsTestSkips::REGISTRY.key?('TestFake#test_bogus')
    raise 'bogus skip mutation did not add TestFake#test_bogus to the throwaway registry'
  end
  # Harness loaded TestFake#test_bogus but reported no omission for the bogus registry entry.
  FipsSkipEnforcement.audit_post_run!(
    known_drop: [],
    hybrid: [],
    artifact: [],
    native: [],
    registry: FipsTestSkips::REGISTRY,
    runner_registry: FipsTestSkips::RUNNER_REGISTRY,
    loaded_test_keys: ['TestFake#test_bogus']
  )
  raise 'bogus skip audit should have failed completeness enforcement'
when 'invert_probe'
  entry = FipsTestSkips::REGISTRY['TestCipher#test_encrypt_decrypt_des_variations']
  FipsSkipEnforcement.execute_probe!(FipsSkipEnforcement::ProbeContext.new, entry)
  raise 'inverted probe should have failed'
else
  raise "unknown mutation #{mutation.inspect}"
end
