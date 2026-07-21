#-*- mode: ruby -*-

Gem::Specification.new do |s|
  s.name = 'jruby-openssl-fips'

  version_rb = File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))
  version_rb = File.read(version_rb)
  s.version = version_rb.match( /.*\sVERSION\s*=\s*['"](.*)['"]/ )[1]

  s.platform = 'java'
  s.authors = ['Karol Bucek', 'Ola Bini', 'JRuby contributors']
  s.email = 'self+jruby-openssl@kares.org'
  s.summary = "JRuby OpenSSL for deployment-provided Bouncy Castle FIPS"
  s.homepage = 'https://github.com/jruby/jruby-openssl'
  s.description = 'JRuby-OpenSSL for FIPS deployments. This gem bundles no Bouncy Castle jars; the deployment must provide compatible bc-fips, bcpkix-fips, bctls-fips, and bcutil-fips jars on the JVM classpath.'
  s.licenses = [ 'EPL-1.0', 'GPL-2.0', 'LGPL-2.1' ]

  s.require_paths = ['lib']

  s.files = `git ls-files`.split("\n").
    select { |f| f =~ /^(lib)/ ||
                 f =~ /^(History|LICENSE|README|Rakefile|Mavenfile|pom.xml)/i } +
    Dir.glob('lib/jopenssl.jar')

  s.required_ruby_version = '>= 2.5.0' # JRuby >= 9.2

  s.metadata = {
    'bouncy_castle_fips_jars' =>
      'bc-fips 2.0.1, bcpkix-fips 2.0.7, bctls-fips 2.0.22, bcutil-fips 2.0.5'
  }
end

# vim: syntax=Ruby
