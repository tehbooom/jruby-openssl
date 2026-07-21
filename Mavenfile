#-*- mode: ruby -*-

gemspec :jar => 'jopenssl', :include_jars => true

distribution_management do
  snapshot_repository :id => :ossrh, :url => 'https://oss.sonatype.org/content/repositories/snapshots'
  repository :id => :ossrh, :url => 'https://oss.sonatype.org/service/local/staging/deploy/maven2/'
end

java_target = '1.8'
gen_sources = '${basedir}/target/generated-sources' # hard-coded in AnnotationBinder

plugin( 'org.codehaus.mojo:exec-maven-plugin', '3.5.0' ) do

=begin
  invoker_main  = '-Djruby.bytecode.version=${compiler.target}'
  #invoker_main << ' -classpath '
  invoker_main << ' org.jruby.anno.InvokerGenerator'
  invoker_main << " #{gen_sources}/annotated_classes.txt ${project.build.outputDirectory}"

  dependency 'org.jruby', 'jruby-core', '${jruby.version}'

  execute_goal :java, :id => 'invoker-generator', :phase => 'process-classes',
      :mainClass => 'org.jruby.anno.InvokerGenerator', :classpathScope => 'compile',
      #:arguments => [ '${gen.sources}/annotated_classes.txt', '${project.build.outputDirectory}' ] do
      :commandlineArgs => "#{gen_sources}/annotated_classes.txt ${project.build.outputDirectory}",
      :classpathScope => 'runtime', :additionalClasspathElements => [ '${project.build.outputDirectory}' ],
      :includeProjectDependencies => false, :includePluginDependencies => true do

    #systemProperties do
    #  property '-Djruby.bytecode.version=${compiler.target}'
    #end
=end

  execute_goal :exec, :id => 'invoker-generator', :phase => 'process-classes',
      :executable => 'java', :classpathScope => 'compile',
      :arguments => [ "-Djruby.bytecode.version=#{java_target}",
                      '-classpath', xml( '<classpath/>' ),
                      'org.jruby.anno.InvokerGenerator',
                      "#{gen_sources}/annotated_classes.txt",
                      '${project.build.outputDirectory}' ]
end

plugin( 'org.codehaus.mojo:build-helper-maven-plugin', '3.6.1' ) do
  execute_goal 'add-source', :phase => 'process-classes', :sources => [ gen_sources ]
end

compiler_configuration = {
    :source => '1.8', :target => java_target, :release => '8',
    :encoding => 'UTF-8', :debug => true,
    :showWarnings => true, :showDeprecation => true,
    :excludes => [ 'module-info.java' ],
    #:jdkToolchain => { :version => '[1.7,11)' },
    :generatedSourcesDirectory => gen_sources,
    :annotationProcessors => [ 'org.jruby.anno.AnnotationBinder' ]
}
compiler_configuration.delete(:release) if ENV_JAVA['java.specification.version'] == '1.8'

plugin( :compiler, '3.15.0', compiler_configuration) do

  #execute_goal :compile, :id => 'annotation-binder', :phase => 'compile',
  #    :generatedSourcesDirectory => gen_sources, #:outputDirectory => gen_sources,
  #    :annotationProcessors => [ 'org.jruby.anno.AnnotationBinder' ],
  #    :proc => 'only', # :compilerReuseStrategy => 'alwaysNew',
  #    :useIncrementalCompilation => false, :fork => true, :verbose => true,
  #    :compilerArgs => [ '-XDignore.symbol.file=true', '-J-Dfile.encoding=UTF-8' ]

  execute_goal :compile,
               :id => 'compile-populators', :phase => 'process-classes',
               :includes => [ 'org/jruby/gen/**/*.java' ],
               :optimize => true,
               :compilerArgs => [ '', '-XDignore.symbol.file=true' ]
end

plugin :clean do
  execute_goals( 'clean', :id => 'default-clean', :phase => 'clean',
                 'filesets' => [
                    { :directory => 'lib', :includes => [ 'jopenssl.jar' ] },
                    { :directory => 'lib/org' },
                    { :directory => 'target', :includes => [ '*' ] }
                 ],
                 'failOnError' =>  'false' )
end

jruby_compile_compat = '9.2.1.0'
jar 'org.jruby:jruby-core', jruby_compile_compat, :scope => :provided
# for invoker generated classes we need to add javax.annotation when on Java > 8
jar 'javax.annotation:javax.annotation-api', '1.3.1', :scope => :compile
jar 'org.junit.jupiter:junit-jupiter', '5.11.4', :scope => :test
# a test dependency to provide digest and other stdlib bits, needed when loading OpenSSL in Java unit tests
jar 'org.jruby:jruby-stdlib', jruby_compile_compat, :scope => :test

plugin :surefire, '3.5.5' do
  # FIPS-only tests require -Pfips-tests (bc-fips classpath + provider fixture).
  # Keep all FIPS-only *Test.java classes out of the default non-FIPS surefire run.
  execute_goal :test, :id => 'default-test',
    :excludes => [
      '**/Fips*Test.java'
    ]
end

# NOTE: to build on Java 11 - installing gems fails (due old jossl) with:
#  load error: jopenssl/load -- java.lang.StringIndexOutOfBoundsException
MVN_JRUBY_VERSION = '9.2.19.0'

jruby_plugin! :gem do
  # when installing dependent gems we want to use the built in openssl not the one from this lib directory
  execute_goal :initialize, :id => 'default-initialize', :addProjectClasspath => false, :libDirectory => 'something-which-does-not-exists'
  execute_goal :id => 'default-package', :addProjectClasspath => false, :libDirectory => 'something-which-does-not-exists'
  execute_goals :id => 'default-push', :skip => true
end

# we want to have the snapshots on oss.sonatype.org and the released gems on maven central
plugin :deploy, '3.1.4' do
  execute_goals( :deploy, :skip => false )
end

supported_bc_versions = %w{ 1.78 1.79 1.80 1.81 1.82 1.83 1.84 }

default_bc_version = File.read File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))
default_bc_version = default_bc_version[/BOUNCY_CASTLE_VERSION\s?=\s?'(.*?)'/, 1]

properties( 'jruby.plugins.version' => '3.0.6',
            'jruby.switches' => '-W0', # https://github.com/torquebox/jruby-maven-plugins/issues/94
            'bc.versions' => default_bc_version,
            'invoker.test' => '${bc.versions}',
            # allow to skip all tests with -Dmaven.test.skip
            'invoker.skip' => '${maven.test.skip}',
            'skipRunit' => 'true',
            'runit.dir' => 'src/test/ruby/**/test_*.rb',
            'mavengem.wagon.version' => '2.0.2', # for jruby plugin
            'mavengem-wagon.version' => '3.0.0', # for polyglot-ruby
            # use this version of jruby for the jruby-maven-plugins
            'jruby.versions' => MVN_JRUBY_VERSION, 'jruby.version' => MVN_JRUBY_VERSION,
            # dump pom.xml when running 'rmvn'
            'polyglot.dump.pom' => 'pom.xml', 'polyglot.dump.readonly' => false )

# make sure we have the embedded jars in place before we run runit plugin
plugin! :dependency do
  execute_goal 'copy-dependencies',
               :phase => 'generate-test-resources',
               :outputDirectory => '${basedir}/lib',
               :useRepositoryLayout => true,
               :includeGroupIds => 'org.bouncycastle'
end

jruby_plugin(:runit) { execute_goal( :test, :runitDirectory => '${runit.dir}' ) }

invoker_run_options = {
    :id => 'tests-with-different-bc-versions',
    :projectsDirectory => 'integration',
    :pomIncludes => [ '*/pom.xml' ],
    :streamLogs => true,
    # pass those properties on to the test project
    :properties => {
      'jruby.versions' => '${jruby.versions}',
      'jruby.modes' => '${jruby.modes}',
      'jruby.openssl.version' => '${project.version}',
      'bc.versions' => '${bc.versions}',
      'runit.dir' => '${runit.dir}' }
}

jruby_versions = []
jruby_versions += %w{ 9.2.19.0 9.2.20.1 }
jruby_versions += %w{ 9.3.3.0 9.3.13.0 }
jruby_versions += %w{ 9.4.8.0 9.4.14.0 }
jruby_versions += %w{ 10.0.2.0 }

jruby_versions.each do |version|
  profile :id => "test-#{version}" do
    plugin :invoker, '3.8.1' do
      execute_goals( :install, :run, invoker_run_options )
    end
    properties 'jruby.version' => version,
               'jruby.versions' => version,
               'bc.versions' => supported_bc_versions.join(',')
  end
end

profile :id => 'release' do
  plugin :gpg, '3.1.0' do
    execute_goal :sign, :phase => :verify
  end
end

# Run only the strict provider contract against bc-fips, with non-FIPS BC absent.
profile :id => 'fips-tests' do
  dependency 'org.bouncycastle', 'bc-fips', '2.0.1', :scope => :test
  dependency 'org.bouncycastle', 'bcpkix-fips', '2.0.7', :scope => :test
  dependency 'org.bouncycastle', 'bcutil-fips', '2.0.5', :scope => :test
  dependency 'org.bouncycastle', 'bctls-fips', '2.0.22', :scope => :test

  properties 'fips.gem.home' => '${basedir}/pkg/rubygems-fips',
             'test' => 'FipsProviderContractTest,FipsRubyCoverageTest,FipsSkipEnforcementTest,Group1PemBehaviorTest,Group4BehaviorTest,SecurityHelperTest#mismatchedRequiredProviderVersionFailsLoud,SecurityHelperTest#missingRequiredProviderFailsLoud,SecurityHelperTest#requiredProviderNeverFallsBackForUnsupportedAlgorithm,SecurityHelperTest#requiredProviderNeverFallsBackForKeyStore,SecurityHelperTest#strictOcspBuildersIgnoreRegisteredNonFipsBc,SecurityHelperTest#requiredProvidersNeverFallbackAcrossWrapperAudit,SecurityHelperTest#requiredSslProviderRoutesByRegisteredNameAndFailsAfterRemoval,SecurityHelperTest#requiredSslProviderNeverFallsBackForUnsupportedProtocol,SecurityHelperTest#strictJceWithoutRequiredSslProviderFailsLoud,SecurityHelperTest#strictLegacyBcjsseLookupNeverConstructsUnregisteredProvider,SecurityHelperTest#missingRequiredSslProviderFailsBeforeLegacyInstantiation,SecurityHelperTest#strictCrlVerificationNeverUsesBcOrJdkFallback'

  plugin_repository :id => 'mavengems', :url => 'mavengem:https://rubygems.org'

  jruby_plugin :gem, :gemHomes => { 'fips-ruby' => '${fips.gem.home}' } do
    execute_goal :initialize, :id => 'fips-ruby-test-gems', :phase => 'generate-test-resources'
    gem 'test-unit', '3.6.7'
    gem 'power_assert', '2.0.3'
    gem 'mocha', '1.16.1'
  end

  plugin! :dependency do
    execute_goal 'copy-dependencies',
                 :id => 'fips-copy-bc-fips',
                 :phase => 'generate-test-resources',
                 :outputDirectory => '${basedir}/lib',
                 :useRepositoryLayout => true,
                 :includeGroupIds => 'org.bouncycastle',
                 :includeArtifactIds => 'bc-fips,bcpkix-fips,bcutil-fips,bctls-fips'
  end

  plugin :surefire, '3.5.5' do
    execute_goal :test, :id => 'default-test', :skip => true
    execute_goal :test, :id => 'fips-provider-contract',
      :argLine => '--add-opens java.base/java.security.cert=ALL-UNNAMED',
      :includes => [
        '**/FipsProviderContractTest.java',
        '**/FipsRubyCoverageTest.java',
        '**/FipsSkipEnforcementTest.java',
        '**/Group1PemBehaviorTest.java',
        '**/Group4BehaviorTest.java'
      ],
      :classpathDependencyExcludes => [
        'org.bouncycastle:bcprov-jdk18on',
        'org.bouncycastle:bcpkix-jdk18on',
        'org.bouncycastle:bctls-jdk18on',
        'org.bouncycastle:bcutil-jdk18on'
      ],
      # The regression fixtures intentionally reuse RSA keys for certificate
      # signing and TLS key exchange.
      :systemPropertyVariables => {
        'org.bouncycastle.rsa.allow_multi_use' => 'true'
      }
  end
end

# vim: syntax=Ruby
