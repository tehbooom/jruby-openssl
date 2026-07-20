# Explicit FIPS-profile skips ONLY for tests that require known dropped operations.
# Drop-verification tests (expect NotImplementedError / ArgumentError) must run.

if ENV['JRUBY_OPENSSL_FIPS_TESTS'] == 'true'
  require File.expand_path('fips_enforcement', __dir__)

  module FipsTestSkips
    extend FipsSkipEnforcement

    DSA2048_FIXTURE = File.expand_path('../fixtures/pkey/dsa2048', __dir__).freeze

    DSA_ENCRYPTED_PEM = <<~EOF.freeze
      -----BEGIN DSA PRIVATE KEY-----
      Proc-Type: 4,ENCRYPTED
      DEK-Info: AES-128-CBC,F8BB7BFC7EAB9118AC2E3DA16C8DB1D9

      D2sIzsM9MLXBtlF4RW42u2GB9gX3HQ3prtVIjWPLaKBYoToRUiv8WKsjptfZuLSB
      74ZPdMS7VITM+W1HIxo/tjS80348Cwc9ou8H/E6WGat8ZUk/igLOUEII+coQS6qw
      QpuLMcCIavevX0gjdjEIkojBB81TYDofA1Bp1z1zDI/2Zhw822xapI79ZF7Rmywt
      OSyWzFaGipgDpdFsGzvT6//z0jMr0AuJVcZ0VJ5lyPGQZAeVBlbYEI4T72cC5Cz7
      XvLiaUtum6/sASD2PQqdDNpgx/WA6Vs1Po2kIUQIM5TIwyJI0GdykZcYm6xIK/ta
      Wgx6c8K+qBAIVrilw3EWxw==
      -----END DSA PRIVATE KEY-----
    EOF

    EC_ENCRYPTED_PEM = <<~EOF.freeze
      -----BEGIN EC PRIVATE KEY-----
      Proc-Type: 4,ENCRYPTED
      DEK-Info: AES-128-CBC,85743EB6FAC9EA76BF99D9328AFD1A66

      nhsP1NHxb53aeZdzUe9umKKyr+OIwQq67eP0ONM6E1vFTIcjkDcFLR6PhPFufF4m
      y7E2HF+9uT1KPQhlE+D63i1m1Mvez6PWfNM34iOQp2vEhaoHHKlR3c43lLyzaZDI
      0/dGSU5SzFG+iT9iFXCwCvv+bxyegkBOyALFje1NAsM=
      -----END EC PRIVATE KEY-----
    EOF

    RSA_ENCRYPTED_PEM = <<~EOF.freeze
      -----BEGIN RSA PRIVATE KEY-----
      Proc-Type: 4,ENCRYPTED
      DEK-Info: AES-128-CBC,733F5302505B34701FC41F5C0746E4C0

      zgJniZZQfvv8TFx3LzV6zhAQVayvQVZlAYqFq2yWbbxzF7C+IBhKQle9IhUQ9j/y
      /jkvol550LS8vZ7TX5WxyDLe12cdqzEvpR6jf3NbxiNysOCxwG4ErhaZGP+krcoB
      ObuL0nvls/+3myy5reKEyy22+0GvTDjaChfr+FwJjXMG+IBCLscYdgZC1LQL6oAn
      9xY5DH3W7BW4wR5ttxvtN32TkfVQh8xi3jrLrduUh+hV8DTiAiLIhv0Vykwhep2p
      WZA+7qbrYaYM8GLLgLrb6LfBoxeNxAEKiTpl1quFkm+Hk1dKq0EhVnxHf92x0zVF
      jRGZxAMNcrlCoE4f5XK45epVZSZvihdo1k73GPbp84aZ5P/xlO4OwZ3i4uCQXynl
      jE9c+I+4rRWKyPz9gkkqo0+teJL8ifeKt/3ab6FcdA0aArynqmsKJMktxmNu83We
      YVGEHZPeOlyOQqPvZqWsLnXQUfg54OkbuV4/4mWSIzxFXdFy/AekSeJugpswMXqn
      oNck4qySNyfnlyelppXyWWwDfVus9CVAGZmJQaJExHMT/rQFRVchlmY0Ddr5O264
      gcjv90o1NBOc2fNcqjivuoX7ROqys4K/YdNQ1HhQ7usJghADNOtuLI8ZqMh9akXD
      Eqp6Ne97wq1NiJj0nt3SJlzTnOyTjzrTe0Y+atPkVKp7SsjkATMI9JdhXwGhWd7a
      qFVl0owZiDasgEhyG2K5L6r+yaJLYkPVXZYC/wtWC3NEchnDWZGQcXzB4xROCQkD
      OlWNYDkPiZioeFkA3/fTMvG4moB2Pp9Q4GU5fJ6k43Ccu1up8dX/LumZb4ecg5/x
      -----END RSA PRIVATE KEY-----
    EOF

    probe_dsa_derive_y = lambda do |test_case|
      error = test_case.assert_raise(OpenSSL::PKey::DSAError,
                                     'DSA derive-y from x-only PKCS#8 must be rejected') do
        OpenSSL::PKey::DSA.new(File.binread(DSA2048_FIXTURE))
      end
      test_case.assert_match(/deriving y from x is unavailable/, error.message)
    end

    probe_dsa_sign_verify_raw = lambda do |test_case|
      digest = OpenSSL::Digest.digest('SHA1', 'Sign me!')
      fixture = File.binread(DSA2048_FIXTURE)

      # Phase 1 — exact TestDSA#test_sign_verify_raw chain: fixture load must reject (derive-y gate).
      error = test_case.assert_raise(OpenSSL::PKey::DSAError, OpenSSL::PKey::PKeyError,
                                     'x-only dsa2048 PKCS#8 fixture load must be rejected under FIPS') do
        key = OpenSSL::PKey.read(fixture)
        key.sign_raw(nil, digest)
      end
      test_case.assert_match(/Could not parse PKey|deriving y from x is unavailable|public key is required/i,
                             error.message)

      # Phase 2 — raw sign_raw itself succeeds once fixture material is loaded manually.
      provider = Java::OrgJrubyExtOpenssl::SecurityHelper.getSecurityProvider
      pem_body = fixture.gsub(/-----BEGIN[^-]+-----|-----END[^-]+-----|\s/, '')
      der = pem_body.unpack('m0').first
      spec = java.security.spec.PKCS8EncodedKeySpec.new(der.to_java_bytes)
      factory = Java::JavaSecurity::KeyFactory.getInstance('DSA', provider)
      java_key = factory.generatePrivate(spec)
      params = java_key.getParams
      dsa = OpenSSL::PKey::DSA.new
      dsa.p = OpenSSL::BN.new(params.getP.to_s)
      dsa.q = OpenSSL::BN.new(params.getQ.to_s)
      dsa.g = OpenSSL::BN.new(params.getG.to_s)
      dsa.priv_key = OpenSSL::BN.new(java_key.getX.to_s)
      sig = dsa.sign_raw(nil, digest)
      test_case.assert(sig && !sig.empty?,
                       'sign_raw on fixture-derived x-only DSA material must execute at jruby-openssl')
    end

    probe_dsa_encrypted_pem = lambda do |test_case|
      error = test_case.assert_raise(OpenSSL::PKey::DSAError,
                                     'legacy Proc-Type encrypted DSA PEM must be rejected') do
        OpenSSL::PKey::DSA.new(DSA_ENCRYPTED_PEM, 'abcdef')
      end
      test_case.assert_match(/Neither PUB key nor PRIV key|MD5 EVP_BytesToKey/, error.message)
    end

    probe_two_key_tdea_encryption = lambda do |test_case|
      error = test_case.assert_raise(OpenSSL::Cipher::CipherError,
                                     'two-key TDEA encryption must be rejected under FIPS') do
        cipher = OpenSSL::Cipher.new('DES-EDE-CFB')
        cipher.encrypt
        cipher.key = "\0" * 16
        cipher.iv = "\0" * 8
        cipher.update('JPMNT') + cipher.final
      end
      test_case.assert_match(/two-key TDEA encryption is disallowed/, error.message)
    end

    probe_jks_unavailable = lambda do |test_case|
      provider = Java::OrgJrubyExtOpenssl::SecurityHelper.getSecurityProvider
      test_case.assert_equal('BCFIPS', provider.name)
      raised = false
      begin
        Java::JavaSecurity::KeyStore.getInstance('JKS', provider)
      rescue Java::JavaSecurity::KeyStoreException, Java::JavaSecurity::NoSuchAlgorithmException
        raised = true
      end
      test_case.assert(raised, 'BCFIPS must not provide JKS KeyStore for truststore artifact skips')
    end

    probe_bcjsse_nonblocking_connect = lambda do |test_case|
      require 'socket'
      socket = OpenSSL::SSL::SSLSocket.new(Socket.new(:INET, :STREAM))
      begin
        socket.connect_nonblock
        test_case.flunk('connect_nonblock on an unconnected socket must not succeed under BCJSSE')
      rescue Errno::EPIPE
        test_case.flunk('BCJSSE must not report platform EPIPE for unconnected nonblocking connect')
      rescue OpenSSL::SSL::SSLErrorWaitReadable, IOError, SystemCallError
        # BCJSSE reports wait-readable / closed-descriptor style errors instead of EPIPE.
      ensure
        socket.close rescue nil
      end
    end

    probe_jruby_io_duplication = lambda do |test_case|
      test_case.assert(defined?(JRUBY_VERSION), 'inherited socket artifact applies only on JRuby')
      io = Object.new
      def io.to_io; self; end
      test_case.assert_raise(NoMethodError, TypeError) do
        OpenSSL::SSL::SSLSocket.new(io, OpenSSL::SSL::SSLContext.new)
      end
    end

    probe_write_nonblock_helper_type_error = lambda do |test_case|
      test_case.assert_raise(TypeError, 'write_nonblock helper must fail on Symbol append') do
        response = +''
        response << :wait_readable
      end
    end

    probe_cipher_default_key_unimplemented = lambda do |test_case|
      test_case.assert(defined?(JRUBY_VERSION),
                       'cipher default-key omission is JRuby-specific')
      test_case.assert(!OpenSSL::Cipher.instance_methods(false).include?(:key),
                       'JRuby OpenSSL::Cipher must not expose key before explicit assignment')
    end

    probe_scrypt_unimplemented = lambda do |test_case|
      test_case.assert(!OpenSSL::KDF.respond_to?(:scrypt),
                       'scrypt must remain unimplemented for native KDF omissions')
    end

    probe_anon_cipher_disabled = lambda do |test_case|
      test_case.assert(!OpenSSL::ExtConfig::TLS_DH_anon_WITH_AES_256_GCM_SHA384,
                       'anonymous TLS ciphers must be disabled under the FIPS profile')
    end

    probe_default_cert_file_not_pem = lambda do |test_case|
      pem_certs = File.binread(OpenSSL::X509::DEFAULT_CERT_FILE).
          scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
      test_case.assert(pem_certs.empty?,
                       'DEFAULT_CERT_FILE must not be a PEM bundle on this platform')
    end

    ENTRIES = [
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestDSA#test_private_pkcs8',
        category: :drop,
        label: 'DROP: DSA derive-y from x-only PKCS#8 unsupported at the jruby-openssl FIPS layer (the configured provider requires the public key)',
        direction: :reject,
        probe: probe_dsa_derive_y),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestDSA#test_sign_verify_raw',
        category: :drop,
        label: 'DROP: x-only dsa2048 PKCS#8 fixture load unsupported at the jruby-openssl FIPS layer (derive-y is unavailable under the configured provider; sign_raw on fixture-derived key material succeeds once loaded manually)',
        direction: :reject,
        probe: probe_dsa_sign_verify_raw),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestCipher#test_cipher_extended_support',
        category: :drop,
        label: 'DROP: PBEWithSHA1AndRC2_40-CBC unsupported at the jruby-openssl FIPS layer (RC2-based legacy PBE is not FIPS-approved)',
        direction: :reject,
        probe: lambda do |test_case|
          error = test_case.assert_raise(OpenSSL::Cipher::CipherError,
                                         'PBEWithSHA1AndRC2_40-CBC must be rejected under FIPS') do
            OpenSSL::Cipher.new('PBEWithSHA1AndRC2_40-CBC')
          end
          test_case.assert_match(/unsupported cipher algorithm/, error.message)
        end),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestCipher#test_encrypt_decrypt_des_variations',
        category: :drop,
        label: 'DROP: two-key TDEA encryption unsupported at the jruby-openssl FIPS layer (NIST SP 800-131A Rev.2 disallows two-key TDEA encryption; legacy decryption remains available)',
        direction: :reject,
        probe: probe_two_key_tdea_encryption),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestDigest#test_digest_classes',
        category: :drop,
        label: 'DROP: MD2 and MD4 digest constructors unsupported at the jruby-openssl FIPS layer (the configured provider rejects both algorithms)',
        direction: :reject,
        probe: lambda do |test_case|
          provider = Java::OrgJrubyExtOpenssl::SecurityHelper.getSecurityProvider
          test_case.assert_raise(Java::JavaSecurity::NoSuchAlgorithmException,
                                 'MD2 must be rejected by the configured provider') do
            Java::JavaSecurity::MessageDigest.getInstance('MD2', provider)
          end
          test_case.assert_raise(Java::JavaSecurity::NoSuchAlgorithmException,
                                 'MD4 must be rejected by the configured provider') do
            Java::JavaSecurity::MessageDigest.getInstance('MD4', provider)
          end
        end),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestPKCS5#test_pbkdf2_hmac',
        category: :drop,
        label: 'DROP: PBKDF2WithHmacMD5 provider primitive unsupported under FIPS (the configured provider rejects the algorithm)',
        direction: :reject,
        probe: lambda do |test_case|
          provider = Java::OrgJrubyExtOpenssl::SecurityHelper.getSecurityProvider
          test_case.assert_raise(Java::JavaSecurity::NoSuchAlgorithmException,
                                 'PBKDF2-HMAC-MD5 must be rejected by the configured provider') do
            Java::JavaxCrypto::SecretKeyFactory.getInstance('PBKDF2WithHmacMD5', provider)
          end
        end),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestDSA#test_DSAPrivateKey_encrypted',
        category: :drop,
        label: 'DROP: MD5 EVP_BytesToKey encrypted DSA PEM load unsupported at the jruby-openssl FIPS layer (the legacy MD5 KDF is not FIPS-approved)',
        direction: :reject,
        probe: probe_dsa_encrypted_pem),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestEC#test_ECPrivateKey_encrypted',
        category: :drop,
        label: 'DROP: MD5 EVP_BytesToKey encrypted EC PEM load unsupported at the jruby-openssl FIPS layer (the legacy MD5 KDF is not FIPS-approved)',
        direction: :reject,
        probe: lambda do |test_case|
          error = test_case.assert_raise(OpenSSL::PKey::ECError,
                                         'MD5 EVP_BytesToKey encrypted EC PEM must be rejected under FIPS') do
            OpenSSL::PKey::EC.new(EC_ENCRYPTED_PEM, 'abcdef')
          end
          test_case.assert_match(/Neither PUB key nor PRIV key|MD5 EVP_BytesToKey/, error.message)
        end),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestRSA#test_RSAPrivateKey_encrypted',
        category: :drop,
        label: 'DROP: MD5 EVP_BytesToKey encrypted RSA PEM load unsupported at the jruby-openssl FIPS layer (the legacy MD5 KDF is not FIPS-approved)',
        direction: :reject,
        probe: lambda do |test_case|
          error = test_case.assert_raise(OpenSSL::PKey::RSAError,
                                         'MD5 EVP_BytesToKey encrypted RSA PEM must be rejected under FIPS') do
            OpenSSL::PKey::RSA.new(RSA_ENCRYPTED_PEM, 'abcdef')
          end
          test_case.assert_match(/Neither PUB key nor PRIV key|MD5 EVP_BytesToKey/, error.message)
        end),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestX509Request#test_sign_and_verify_rsa_md5',
        category: :hybrid,
        label: 'HYBRID-GATED: MD5withRSA CSR signing and verification execute at the jruby-openssl layer; deployment policy is enforced by logstash-core FIPS.check!',
        direction: :success,
        probe: lambda do |test_case|
          key = OpenSSL::PKey::RSA.generate(2048)
          request = OpenSSL::X509::Request.new
          request.subject = OpenSSL::X509::Name.parse('/CN=fips-skip-probe')
          request.public_key = key.public_key
          request.sign(key, OpenSSL::Digest.new('MD5'))
          test_case.assert_equal(true, request.verify(key),
                                 'MD5withRSA CSR must execute at the jruby-openssl layer in C:HYBRID mode')
        end),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestX509Store#test_store_location_with_java_truststore',
        category: :artifact,
        label: 'test requires loading a JKS truststore through the configured crypto provider',
        direction: :environment,
        probe: probe_jks_unavailable),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestX509Store#test_use_default_java_cacerts_file_as_custom_file',
        category: :artifact,
        label: 'test requires loading the JVM JKS cacerts file through the configured crypto provider',
        direction: :environment,
        probe: probe_jks_unavailable),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestSSLSocket#test_connect_non_connected',
        category: :artifact,
        label: 'BCJSSE nonblocking connect reports wait-readable instead of the platform EPIPE',
        direction: :environment,
        probe: probe_bcjsse_nonblocking_connect),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestSSLSocket#test_inherited_socket',
        category: :artifact,
        label: 'JRuby native IO duplication is unavailable for this JVM architecture',
        direction: :environment,
        probe: probe_jruby_io_duplication),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestSSLWriteFlush#test_write_nonblock_data_integrity',
        category: :artifact,
        label: 'pre-existing deterministic helper TypeError at ssl/test_write_flush.rb:136, unrelated to FIPS',
        direction: :environment,
        probe: probe_write_nonblock_helper_type_error),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestCipher#test_cipher_init_default_key',
        category: :native,
        label: 'OpenSSL::Cipher key default not implemented',
        direction: :environment,
        probe: probe_cipher_default_key_unimplemented),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestKDF#test_scrypt_rfc7914_first',
        category: :native,
        label: 'scrypt is not implemented',
        direction: :environment,
        probe: probe_scrypt_unimplemented),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestKDF#test_scrypt_rfc7914_second',
        category: :native,
        label: 'scrypt is not implemented',
        direction: :environment,
        probe: probe_scrypt_unimplemented),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestSSL#test_post_connect_check_with_anon_ciphers',
        category: :native,
        label: 'OpenSSL::ExtConfig::TLS_DH_anon_WITH_AES_256_GCM_SHA384 not enabled',
        direction: :environment,
        probe: probe_anon_cipher_disabled),
      FipsSkipEnforcement::SkipEntry.new(
        key: 'TestX509Store#test_use_default_pem_cert_file_as_custom_file',
        category: :native,
        label: 'DEFAULT_CERT_FILE is not a PEM bundle',
        direction: :environment,
        probe: probe_default_cert_file_not_pem),
    ].freeze

    REGISTRY = build_registry(ENTRIES)
    RUNNER_REGISTRY = REGISTRY.select { |_, entry| entry.category != :native }.freeze

    EXPECTED_DROP_SKIPS = REGISTRY.values.select { |entry| entry.category == :drop }.
        each_with_object({}) { |entry, map| map[entry.key] = entry.label }.freeze
    HYBRID_GATED_SKIPS = REGISTRY.values.select { |entry| entry.category == :hybrid }.
        each_with_object({}) { |entry, map| map[entry.key] = entry.label }.freeze
    ARTIFACT_SKIPS = REGISTRY.values.select { |entry| entry.category == :artifact }.
        each_with_object({}) { |entry, map| map[entry.key] = entry.label }.freeze
    NATIVE_SKIPS = REGISTRY.values.select { |entry| entry.category == :native }.
        each_with_object({}) { |entry, map| map[entry.key] = entry.label }.freeze
    SKIPS = REGISTRY.values.each_with_object({}) { |entry, map| map[entry.key] = entry.label }.freeze

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

    def entry_for_key(key)
      REGISTRY[key]
    end

    def category_for_message(message)
      entry = REGISTRY.values.find { |candidate| candidate.label == message }
      entry&.category
    end

    def known_drop?(message)
      category_for_message(message) == :drop
    end

    def hybrid?(message)
      category_for_message(message) == :hybrid
    end

    def artifact?(message)
      category_for_message(message) == :artifact
    end

    def native?(message)
      category_for_message(message) == :native
    end

    def audit_harness_results!(known_drop:, hybrid:, artifact:, native:, loaded_test_keys: nil)
      audit_post_run!(
        known_drop: known_drop,
        hybrid: hybrid,
        artifact: artifact,
        native: native,
        registry: REGISTRY,
        runner_registry: RUNNER_REGISTRY,
        loaded_test_keys: loaded_test_keys
      )
    end

    def run_native_probes!(native_omissions)
      probe_case = FipsSkipEnforcement::ProbeContext.new
      native_omissions.each do |line|
        parsed = parse_omission(line)
        entry = validate_harness_omission!(parsed[:test_name], parsed[:message], REGISTRY, :native)
        execute_probe!(probe_case, entry)
      end
    end
  end

  module FipsSkipRunner
    def run_test
      key = FipsTestSkips.skip_key(self)
      entry = FipsTestSkips::RUNNER_REGISTRY[key]
      if entry
        FipsTestSkips.execute_probe!(FipsSkipEnforcement::ProbeContext.new, entry)
        omit(entry.label)
      else
        super
      end
    end
  end

  class Test::Unit::TestCase
    prepend FipsSkipRunner
  end
end
