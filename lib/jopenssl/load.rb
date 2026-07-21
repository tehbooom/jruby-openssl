require 'jopenssl/version'

fips_artifact = defined?(Gem) && Gem.loaded_specs.key?('jruby-openssl-fips')

if fips_artifact
  required_fips_classes = {
    'bc-fips 2.0.1' => 'org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider',
    'bcpkix-fips 2.0.7' => 'org.bouncycastle.operator.jcajce.JcaContentSignerBuilder',
    'bctls-fips 2.0.22' => 'org.bouncycastle.jsse.provider.BouncyCastleJsseProvider',
    'bcutil-fips 2.0.5' => 'org.bouncycastle.asn1.cms.CMSObjectIdentifiers'
  }
  missing_fips_jars = required_fips_classes.each_with_object([]) do |(jar, class_name), missing|
    begin
      Java::JavaLang::Class.forName(class_name)
    rescue Java::JavaLang::ClassNotFoundException
      missing << jar
    end
  end
  unless missing_fips_jars.empty?
    raise LoadError, "jruby-openssl-fips bundles no Bouncy Castle jars; provide the " \
      "Bouncy Castle FIPS jars on the JVM classpath (tested set: bc-fips 2.0.1, " \
      "bcpkix-fips 2.0.7, bctls-fips 2.0.22, bcutil-fips 2.0.5). " \
      "Missing: #{missing_fips_jars.join(', ')}"
  end
elsif !ENV_JAVA['jruby.openssl.load.jars'].eql?('false')
  version = JOpenSSL::BOUNCY_CASTLE_VERSION
  begin
    require 'jar-dependencies'
    # if we have jar-dependencies we let it track the jars
    require_jar 'org.bouncycastle', 'bcprov-jdk18on', version
    require_jar 'org.bouncycastle', 'bcpkix-jdk18on', version
    require_jar 'org.bouncycastle', 'bcutil-jdk18on', version
    require_jar 'org.bouncycastle', 'bctls-jdk18on',  version
    bc_jars = true
  rescue LoadError, RuntimeError
    bc_jars = false
  end
  unless bc_jars
    load "org/bouncycastle/bcprov-jdk18on/#{version}/bcprov-jdk18on-#{version}.jar"
    load "org/bouncycastle/bcpkix-jdk18on/#{version}/bcpkix-jdk18on-#{version}.jar"
    load "org/bouncycastle/bcutil-jdk18on/#{version}/bcutil-jdk18on-#{version}.jar"
    load "org/bouncycastle/bctls-jdk18on/#{version}/bctls-jdk18on-#{version}.jar"
  end
end

require 'jopenssl.jar'
JRuby::Util.load_ext('org.jruby.ext.openssl.OpenSSL')

# NOTE: content bellow should live in *lib/openssl.rb* but due RubyGems/Bundler
# `autoload :OpenSSL` this will cause issues if an older version (0.11) is the
# default gem under JRuby 9.2 (which on auto-load does not trigger a dynamic
# require - this is only fixed in JRuby 9.3)

module OpenSSL
  autoload :Config, 'openssl/config' unless const_defined?(:Config, false)
  autoload :ConfigError, 'openssl/config' unless const_defined?(:ConfigError, false)
  autoload :PKCS12, 'openssl/pkcs12'
end

=begin
= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
  All rights reserved.

= Licence
  This program is licensed under the same licence as Ruby.
  (See the file 'LICENCE'.)
=end

require 'openssl/bn'
require 'openssl/pkey'
require 'openssl/cipher'
require 'openssl/digest'
require 'openssl/hmac'
require 'openssl/x509'
require 'openssl/ssl'
require 'openssl/pkcs5'

module OpenSSL
  # call-seq:
  #   OpenSSL.secure_compare(string, string) -> boolean
  #
  # Constant time memory comparison. Inputs are hashed using SHA-256 to mask
  # the length of the secret. Returns +true+ if the strings are identical,
  # +false+ otherwise.
  def self.secure_compare(a, b)
    hashed_a = OpenSSL::Digest.digest('SHA256', a)
    hashed_b = OpenSSL::Digest.digest('SHA256', b)
    OpenSSL.fixed_length_secure_compare(hashed_a, hashed_b) && a == b
  end
end
