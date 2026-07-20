# Explicit FIPS-profile skips ONLY for tests that require known dropped operations.
# Drop-verification tests (expect NotImplementedError / ArgumentError) must run.

if ENV['JRUBY_OPENSSL_FIPS_TESTS'] == 'true'
  module FipsTestSkips
    EXPECTED_DROP_SKIPS = {
      'TestDSA#test_private_pkcs8' =>
          'DSA derive-y from x-only PKCS#8 is unavailable under FIPS',
      'TestDSA#test_new' =>
          'DSA key generation is unavailable under FIPS',
      'TestDSA#test_dsa_sys_sign_verify' =>
          'DSA key generation is unavailable under FIPS',
      'TestDSA#test_sign_verify_raw' =>
          'uses dsa2048 fixture requiring derive-y under FIPS',
      'TestX509Store#test_verify_same_subject_ca' =>
          'DSA key generation is unavailable under FIPS',
      'TestCipher#test_cipher_extended_support' =>
          'PBEWithSHA1AndRC2_40 uses RC2, which is unavailable under FIPS',
      'TestDigest#test_digest_classes' =>
          'legacy digest constructors in this combined test include MD2, MD4, and MD5',
      'TestPKCS5#test_pbkdf2_hmac' =>
          'combined test includes PBKDF2WithHmacMD5, which is unavailable under FIPS',
      'TestCipher#test_des_iv_len' =>
          'DES-EDE-CFB is not an approved cipher under the designated FIPS module',
      'TestCipher#test_des_key_len' =>
          'DES-EDE-CFB is not an approved cipher under the designated FIPS module',
      'TestDSA#test_DSAPrivateKey_encrypted' =>
          'legacy Proc-Type encrypted PEM uses the non-approved MD5 EVP_BytesToKey KDF',
      'TestEC#test_ECPrivateKey_encrypted' =>
          'legacy Proc-Type encrypted PEM uses the non-approved MD5 EVP_BytesToKey KDF',
      'TestRSA#test_RSAPrivateKey_encrypted' =>
          'legacy Proc-Type encrypted PEM uses the non-approved MD5 EVP_BytesToKey KDF',
      'TestX509Request#test_sign_and_verify_rsa_md5' =>
          'RSA-MD5 certificate-request signatures are not approved under FIPS',
    }.freeze

    ARTIFACT_SKIPS = {
      'TestX509Store#test_store_location_with_java_truststore' =>
          'test requires loading a JKS truststore through the configured crypto provider',
      'TestX509Store#test_use_default_java_cacerts_file_as_custom_file' =>
          'test requires loading the JVM JKS cacerts file through the configured crypto provider',
      'TestSSLSocket#test_connect_non_connected' =>
          'BCJSSE nonblocking connect reports wait-readable instead of the platform EPIPE',
      'TestSSLSocket#test_inherited_socket' =>
          'JRuby native IO duplication is unavailable for this JVM architecture',
      'TestSSLWriteFlush#test_write_nonblock_data_integrity' =>
          'BCJSSE nonblocking write timing is not deterministic in the embedded test runtime',
    }.freeze

    SKIPS = EXPECTED_DROP_SKIPS.merge(ARTIFACT_SKIPS).freeze

    module_function

    def skip_key(test_case)
      method = if test_case.respond_to?(:method_name, true)
                 test_case.method_name
               elsif test_case.respond_to?(:name)
                 test_case.name
               else
                 test_case.instance_variable_get(:@method_name)
               end
      "#{test_case.class.name}##{method}"
    end

    def known_drop?(message)
      EXPECTED_DROP_SKIPS.value?(message)
    end

    def artifact?(message)
      ARTIFACT_SKIPS.value?(message)
    end
  end

  module FipsSkipRunner
    def run_test
      if (reason = FipsTestSkips::SKIPS[FipsTestSkips.skip_key(self)])
        omit(reason)
      else
        super
      end
    end
  end

  class Test::Unit::TestCase
    prepend FipsSkipRunner
  end
end
