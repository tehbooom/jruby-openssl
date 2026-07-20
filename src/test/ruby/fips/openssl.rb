# FIPS harness stub for `require 'openssl'`.
#
# lib/openssl.rb pulls jopenssl/load, which eagerly loads openssl/ssl.rb and can
# fail under BCJSSE (JKS not registered). test_helper performs a partial bootstrap
# first; this stub makes incidental `require 'openssl'` calls elsewhere in the
# suite a no-op once core modules are loaded.

unless defined?(OpenSSL::BN)
  raise LoadError,
        'FIPS harness: OpenSSL core must be bootstrapped via test_helper before require "openssl"'
end
