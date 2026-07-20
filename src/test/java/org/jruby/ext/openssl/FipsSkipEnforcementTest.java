package org.jruby.ext.openssl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.jruby.Ruby;
import org.jruby.exceptions.RaiseException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Focused enforcement for the FIPS skip registry: validates that the Ruby
 * registry loads with category/label/probe bindings and that a representative
 * suite run reports zero enforcement failures.
 */
public class FipsSkipEnforcementTest {

    @BeforeAll
    static void enableFipsProfile() throws Exception {
        FipsTestEnvironment.registerConfiguredProviders();
    }

    @AfterAll
    static void disableFipsProfile() {
        FipsTestEnvironment.removeConfiguredProviders();
    }

    @Test
    void skipRegistryLoadsWithExpectedInventory() {
        final Ruby runtime = Ruby.newInstance();
        try {
            bootstrapRuby(runtime);
            runtime.evalScriptlet("ENV['JRUBY_OPENSSL_FIPS_TESTS'] = 'true'");
            runtime.evalScriptlet("require " + quote(new java.io.File("src/test/ruby/fips/fips_skips.rb").getAbsolutePath()));
            assertEquals(9, runtime.evalScriptlet("FipsTestSkips::EXPECTED_DROP_SKIPS.size").convertToInteger().getIntValue());
            assertEquals(1, runtime.evalScriptlet("FipsTestSkips::HYBRID_GATED_SKIPS.size").convertToInteger().getIntValue());
            assertEquals(5, runtime.evalScriptlet("FipsTestSkips::ARTIFACT_SKIPS.size").convertToInteger().getIntValue());
            assertEquals(5, runtime.evalScriptlet("FipsTestSkips::NATIVE_SKIPS.size").convertToInteger().getIntValue());
            assertEquals(20, runtime.evalScriptlet("FipsTestSkips::REGISTRY.size").convertToInteger().getIntValue());
            runtime.evalScriptlet(
                    "FipsTestSkips::REGISTRY.each_value do |entry|\n" +
                    "  raise entry.key unless entry.label.start_with?('DROP:', 'HYBRID-GATED:') || entry.category == :artifact || entry.category == :native\n" +
                    "end\n");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void cipherSuiteEnforcementPassesWithDesDrop() {
        runRubySuiteExpectingPass("cipher", "src/test/ruby/test_cipher.rb");
    }

    @Test
    void pkeySuiteEnforcementPassesWithRawSignProbe() {
        runRubySuiteExpectingPass("pkey", String.join(java.io.File.pathSeparator,
                "src/test/ruby/test_pkey.rb",
                "src/test/ruby/test_pkey_dh.rb",
                "src/test/ruby/rsa/test_rsa.rb",
                "src/test/ruby/ec/test_ec.rb",
                "src/test/ruby/dsa/test_dsa.rb",
                "src/test/ruby/pkey/test_pkey_eddsa.rb"));
    }

    @Test
    void mutationCoherentDropToHybridRedsOnProbeBehaviorMismatch() throws IOException {
        expectMutationReds("drop_to_hybrid", mutateCoherentDropToHybrid(tempFipsCopy()));
    }

    @Test
    void mutationCoherentHybridToDropRedsOnProbeBehaviorMismatch() throws IOException {
        expectMutationReds("hybrid_to_drop", mutateCoherentHybridToDrop(tempFipsCopy()));
    }

    @Test
    void mutationBogusSkipRedsAtAudit() throws IOException {
        expectMutationReds("bogus_skip", mutateBogusArtifactSkip(tempFipsCopy()));
    }

    @Test
    void mutationInvertedProbeAssertionRedsAtProbeExecution() throws IOException {
        expectMutationReds("invert_probe", mutateInvertedDesProbe(tempFipsCopy()));
    }

    private static Path tempFipsCopy() throws IOException {
        final Path dir = Files.createTempDirectory("fips-skip-mutation-");
        Files.copy(Paths.get("src/test/ruby/fips/fips_skips.rb"), dir.resolve("fips_skips.rb"));
        Files.copy(Paths.get("src/test/ruby/fips/fips_enforcement.rb"), dir.resolve("fips_enforcement.rb"));
        return dir;
    }

    private static String readUtf8(final Path path) throws IOException {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    private static void writeUtf8(final Path path, final String text) throws IOException {
        Files.write(path, text.getBytes(StandardCharsets.UTF_8));
    }

    private static Path mutateCoherentDropToHybrid(final Path dir) throws IOException {
        final Path skips = dir.resolve("fips_skips.rb");
        writeUtf8(skips, readUtf8(skips).replaceFirst(
                "(?s)(key: 'TestCipher#test_cipher_extended_support',\\R\\s+)category: :drop,\\R\\s+"
                        + "label: 'DROP:[^']+',\\R\\s+direction: :reject,",
                "$1category: :hybrid,\n"
                        + "        label: 'HYBRID-GATED: PBEWithSHA1AndRC2_40-CBC executes at the jruby-openssl layer (coherent mutation)',\n"
                        + "        direction: :success,"));
        return dir;
    }

    private static Path mutateCoherentHybridToDrop(final Path dir) throws IOException {
        final Path skips = dir.resolve("fips_skips.rb");
        writeUtf8(skips, readUtf8(skips).replaceFirst(
                "(?s)(key: 'TestX509Request#test_sign_and_verify_rsa_md5',\\R\\s+)category: :hybrid,\\R\\s+"
                        + "label: 'HYBRID-GATED:[^']+',\\R\\s+direction: :success,",
                "$1category: :drop,\n"
                        + "        label: 'DROP: MD5withRSA CSR signing blocked under FIPS (coherent mutation)',\n"
                        + "        direction: :reject,"));
        return dir;
    }

    private static Path mutateBogusArtifactSkip(final Path dir) throws IOException {
        final Path skips = dir.resolve("fips_skips.rb");
        final String bogusEntry =
                "\n      FipsSkipEnforcement::SkipEntry.new(\n"
                + "        key: 'TestFake#test_bogus',\n"
                + "        category: :artifact,\n"
                + "        label: 'bogus mutation artifact skip for enforcement completeness testing',\n"
                + "        direction: :environment,\n"
                + "        probe: lambda do |test_case|\n"
                + "          test_case.assert(defined?(JRUBY_VERSION), 'bogus artifact probe')\n"
                + "        end)";
        writeUtf8(skips, readUtf8(skips).replaceFirst(
                "probe: probe_default_cert_file_not_pem\\),\\n    \\]\\.freeze\\n\\n    REGISTRY = build_registry\\(ENTRIES\\)",
                "probe: probe_default_cert_file_not_pem),"
                        + bogusEntry
                        + "\n    ].freeze\n\n    REGISTRY = build_registry(ENTRIES)"));
        return dir;
    }

    private static Path mutateInvertedDesProbe(final Path dir) throws IOException {
        final Path skips = dir.resolve("fips_skips.rb");
        final String invertedProbe =
                "probe_two_key_tdea_encryption = lambda do |test_case|\n"
                + "      cipher = OpenSSL::Cipher.new('DES-EDE-CFB')\n"
                + "      cipher.encrypt\n"
                + "      cipher.key = \"\\0\" * 16\n"
                + "      cipher.iv = \"\\0\" * 8\n"
                + "      cipher.update('JPMNT') + cipher.final\n"
                + "    end";
        writeUtf8(skips, readUtf8(skips).replaceFirst(
                "(?s)probe_two_key_tdea_encryption = lambda do \\|test_case\\|.*?\\n    end",
                invertedProbe));
        return dir;
    }

    private static void expectMutationReds(final String mutation, final Path fipsDir) {
        final Ruby runtime = Ruby.newInstance();
        try {
            bootstrapRuby(runtime);
            runtime.evalScriptlet("ENV['JRUBY_OPENSSL_FIPS_TESTS'] = 'true'");
            runtime.evalScriptlet("$mutation_fips_dir = " + quote(fipsDir.toString()));
            runtime.evalScriptlet("$mutation_name = " + quote(mutation));
            runtime.evalScriptlet(
                    "load " + quote(new java.io.File("src/test/ruby/fips/fips_mutation_runner.rb").getAbsolutePath()));
            throw new AssertionError("mutation " + mutation + " unexpectedly passed");
        }
        catch (RaiseException e) {
            final String message = e.getMessage();
            assertTrue(message != null && !message.isEmpty(),
                    "mutation " + mutation + " failed without reason");
            System.out.println("MUTATION_RED: " + mutation + " REASON: "
                    + message.split("\\R", 2)[0]);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    private static void runRubySuiteExpectingPass(final String suite, final String files) {
        final Ruby runtime = Ruby.newInstance();
        try {
            bootstrapRuby(runtime);
            runtime.evalScriptlet("ENV['JRUBY_OPENSSL_FIPS_TESTS'] = 'true'");
            runtime.evalScriptlet("ENV['FIPS_RUBY_SUITE'] = " + quote(suite));
            runtime.evalScriptlet("ENV['FIPS_RUBY_FILES'] = " + quote(files));
            runtime.evalScriptlet("$fips_harness_findings = []");
            runtime.evalScriptlet(
                    "load " + quote(new java.io.File("src/test/ruby/fips/run_suite.rb").getAbsolutePath()));
            final String json = runtime.evalScriptlet("$fips_ruby_result").toString();
            final int failed = intField(json, "failure_count");
            assertEquals(0, failed, suite + " enforcement failures: " + stringField(json, "failures"));
        }
        catch (RaiseException e) {
            throw new AssertionError(suite + " harness error: " + e.getMessage(), e);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    private static void bootstrapRuby(final Ruby runtime) {
        final String root = new java.io.File("").getAbsolutePath();
        runtime.evalScriptlet("$LOAD_PATH.unshift " + quote(root + "/lib"));
        runtime.evalScriptlet("$LOAD_PATH.unshift " + quote(root + "/src/test/ruby"));
        runtime.evalScriptlet("ENV['GEM_HOME'] = " + quote(root + "/pkg/rubygems-fips"));
        runtime.evalScriptlet("ENV['GEM_PATH'] = " + quote(root + "/pkg/rubygems-fips"));
        runtime.evalScriptlet("require 'rubygems'");
        runtime.evalScriptlet("gem 'test-unit'");
        runtime.evalScriptlet("require 'test/unit'");
        OpenSSL.createOpenSSL(runtime);
        runtime.evalScriptlet("require 'openssl/x509'");
    }

    private static String quote(final String value) {
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }

    private static int intField(final String json, final String field) {
        final String marker = "\"" + field + "\":";
        final int start = json.indexOf(marker);
        if (start < 0) return 0;
        int i = start + marker.length();
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        final int end = i;
        while (i < json.length() && Character.isDigit(json.charAt(i))) i++;
        if (end == i) return 0;
        return Integer.parseInt(json.substring(end, i));
    }

    private static String stringField(final String json, final String field) {
        final String marker = "\"" + field + "\":";
        final int start = json.indexOf(marker);
        if (start < 0) return "";
        int i = start + marker.length();
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length() || json.charAt(i) != '"') return "";
        i++;
        final StringBuilder value = new StringBuilder();
        while (i < json.length()) {
            char c = json.charAt(i++);
            if (c == '"') break;
            value.append(c);
        }
        return value.toString();
    }
}
