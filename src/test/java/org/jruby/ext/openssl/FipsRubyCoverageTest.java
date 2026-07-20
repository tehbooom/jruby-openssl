package org.jruby.ext.openssl;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.jruby.Ruby;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.builtin.IRubyObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * Runs the real Ruby crypto regression suites under the strict FIPS profile.
 * Requires bc-fips on the classpath with non-FIPS BC artifacts excluded by the
 * fips-tests Maven profile.
 *
 * <p>Scope is the eight requested crypto domains (bn, cipher, digest, kdf, pkcs5,
 * pkey, ssl, x509), 366 statically defined test methods across 24 files. The full
 * rake test task matches 39 test-ruby files (including two helper files with no
 * tests) and 523 statically defined test methods; out-of-scope files are listed in
 * printScopeManifest().
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FipsRubyCoverageTest {

    private static final Path PROJECT_ROOT = Paths.get("").toAbsolutePath();
    private static final Path FIPS_GEM_HOME = PROJECT_ROOT.resolve("pkg/rubygems-fips");
    private static final String PATH_SEPARATOR = File.pathSeparator;

    /** Requested-suite files only; 366 {@code def test_*} methods at last audit. */
    private static final Map<String, List<String>> SUITES = new LinkedHashMap<>();

    /**
     * Present in {@code rake test} but outside the eight requested FIPS domains.
     * Listed so nothing is silently omitted.
     */
    private static final Map<String, String> RAKE_ONLY_FILES = new LinkedHashMap<>();

    static {
        SUITES.put("bn", list("src/test/ruby/test_bn.rb"));
        SUITES.put("cipher", list("src/test/ruby/test_cipher.rb"));
        SUITES.put("digest", list("src/test/ruby/test_digest.rb"));
        SUITES.put("kdf", list("src/test/ruby/test_kdf.rb"));
        SUITES.put("pkcs5", list("src/test/ruby/pkcs5/test_pbkdf2.rb"));
        SUITES.put("pkey", list(
                "src/test/ruby/test_pkey.rb",
                "src/test/ruby/test_pkey_dh.rb",
                "src/test/ruby/rsa/test_rsa.rb",
                "src/test/ruby/ec/test_ec.rb",
                "src/test/ruby/dsa/test_dsa.rb",
                "src/test/ruby/pkey/test_pkey_eddsa.rb"));
        SUITES.put("ssl", list(
                "src/test/ruby/ssl/test_ssl.rb",
                "src/test/ruby/ssl/test_socket.rb",
                "src/test/ruby/ssl/test_context.rb",
                "src/test/ruby/ssl/test_session.rb",
                "src/test/ruby/ssl/test_ocsp.rb",
                "src/test/ruby/ssl/test_write_flush.rb"));
        SUITES.put("x509", list(
                "src/test/ruby/x509/test_x509cert.rb",
                "src/test/ruby/x509/test_x509crl.rb",
                "src/test/ruby/x509/test_x509ext.rb",
                "src/test/ruby/x509/test_x509name.rb",
                "src/test/ruby/x509/test_x509req.rb",
                "src/test/ruby/x509/test_x509revoked.rb",
                "src/test/ruby/x509/test_x509store.rb"));

        RAKE_ONLY_FILES.put("test_asn1.rb", "44 tests; ASN.1 not in requested FIPS domains");
        RAKE_ONLY_FILES.put("pkcs7/test_attribute.rb", "1 test; PKCS7 not requested");
        RAKE_ONLY_FILES.put("pkcs7/test_bio.rb", "3 tests; PKCS7 not requested");
        RAKE_ONLY_FILES.put("pkcs7/test_mime.rb", "17 tests; PKCS7 not requested");
        RAKE_ONLY_FILES.put("pkcs7/test_pkcs7.rb", "62 tests; PKCS7 not requested");
        RAKE_ONLY_FILES.put("pkcs7/test_smime.rb", "10 tests; PKCS7 not requested");
        RAKE_ONLY_FILES.put("oaep/test_oaep.rb", "1 test; OAEP not requested");
        RAKE_ONLY_FILES.put("test_hmac.rb", "5 tests; HMAC file separate from test_digest.rb");
        RAKE_ONLY_FILES.put("test_random.rb", "2 tests; Random not requested");
        RAKE_ONLY_FILES.put("test_openssl.rb", "7 tests; OpenSSL meta not requested");
        RAKE_ONLY_FILES.put("test_ns_spki.rb", "4 tests; SPKI not requested");
        RAKE_ONLY_FILES.put("test_security_helper.rb", "1 test; security helper not requested");
        RAKE_ONLY_FILES.put("test_security.rb", "0 tests; placeholder file");
        RAKE_ONLY_FILES.put("test_helper.rb", "0 tests; shared helper matched by Rake glob");
        RAKE_ONLY_FILES.put("ssl/test_helper.rb", "0 tests; SSL helper matched by Rake glob");
    }

    private final Map<String, SuiteResult> suiteResults = new LinkedHashMap<>();
    private final List<String> realFindings = new ArrayList<>();

    @BeforeAll
    static void registerConfiguredProvider() throws Exception {
        FipsTestEnvironment.registerConfiguredProviders();
    }

    @AfterAll
    static void removeConfiguredProvider() {
        FipsTestEnvironment.removeConfiguredProviders();
    }

    @Test
    void nonFipsBcMustRemainAbsent() {
        FipsTestEnvironment.assertNonFipsBcAbsent();
    }

    @Test
    void rubyCryptoSuitesUnderFipsProfile() {
        printScopeManifest();

        for (Map.Entry<String, List<String>> entry : SUITES.entrySet()) {
            final String suite = entry.getKey();
            final SuiteResult result = runSuite(suite, entry.getValue());
            suiteResults.put(suite, result);
            System.out.println(formatSuiteLine(result));

            if (!result.harnessFindings.isEmpty()) {
                final List<String> nonArtifactHarnessFindings = result.harnessFindings.stream()
                        .filter(finding -> !finding.startsWith("HARNESS ARTIFACT:"))
                        .collect(Collectors.toList());
                if (!nonArtifactHarnessFindings.isEmpty()) {
                    realFindings.add(suite + " harness: " +
                            String.join("; ", nonArtifactHarnessFindings));
                }
            }
            if (result.failed > 0) {
                realFindings.add(suite + " failures: " +
                        String.join("; ", truncate(result.failures, 3)));
            }
            if (result.loadError) {
                realFindings.add(suite + " load/setup: " +
                        String.join("; ", result.failures));
            }
        }

        printSummary();

        if (!realFindings.isEmpty()) {
            fail("FIPS Ruby coverage reported real failures (not known-drop skips):\n" +
                    realFindings.stream().collect(Collectors.joining("\n")));
        }
    }

    private static void printScopeManifest() {
        int fipsFiles = 0;
        for (List<String> files : SUITES.values()) {
            fipsFiles += files.size();
        }
        System.out.println("FIPS Ruby scope: 8 requested domains, " + fipsFiles +
                " files, 366 test methods (static def test_ count at last audit)");
        System.out.println("Rake full suite: 39 test*.rb files, 523 test methods defined; " +
                "~520 execute under rake (platform/version conditionals omit a few)");
        System.out.println("Outside FIPS scope (" + (523 - 366) +
                " methods, 16 files, not silently omitted):");
        for (Map.Entry<String, String> entry : RAKE_ONLY_FILES.entrySet()) {
            System.out.println("  - src/test/ruby/" + entry.getKey() + ": " + entry.getValue());
        }
    }

    private SuiteResult runSuite(final String suite, final List<String> files) {
        final Ruby runtime = Ruby.newInstance();
        try {
            bootstrapRuby(runtime);
            runtime.evalScriptlet("ENV['JRUBY_OPENSSL_FIPS_TESTS'] = 'true'");
            runtime.evalScriptlet("ENV['FIPS_RUBY_SUITE'] = " + quote(suite));
            runtime.evalScriptlet("ENV['FIPS_RUBY_FILES'] = " +
                    quote(String.join(PATH_SEPARATOR, files)));
            runtime.evalScriptlet("$fips_harness_findings = []");

            runtime.evalScriptlet(
                    "load " + quote(PROJECT_ROOT.resolve("src/test/ruby/fips/run_suite.rb").toString()));
            final IRubyObject json = runtime.evalScriptlet(
                    "$fips_ruby_result rescue nil");
            if (json == null || json.isNil()) {
                return errorResult(suite, "run_suite.rb did not set $fips_ruby_result");
            }
            return parseResult(json.asJavaString(), suite);
        }
        catch (RaiseException e) {
            return errorResult(suite, "Ruby error: " + e.getMessage());
        }
        catch (RuntimeException e) {
            return errorResult(suite, "Harness error: " + e.getMessage());
        }
        finally {
            runtime.tearDown(false);
        }
    }

    private static SuiteResult errorResult(final String suite, final String message) {
        final SuiteResult result = new SuiteResult();
        result.suite = suite;
        result.failed = 1;
        result.loadError = true;
        result.failures = Collections.singletonList(message);
        return result;
    }

    private static void bootstrapRuby(final Ruby runtime) {
        runtime.evalScriptlet("$LOAD_PATH.unshift " + quote(PROJECT_ROOT.resolve("lib").toString()));
        runtime.evalScriptlet("$LOAD_PATH.unshift " +
                quote(PROJECT_ROOT.resolve("src/test/ruby").toString()));
        runtime.evalScriptlet("ENV['GEM_HOME'] = " + quote(FIPS_GEM_HOME.toString()));
        runtime.evalScriptlet("ENV['GEM_PATH'] = " + quote(FIPS_GEM_HOME.toString()));
        runtime.evalScriptlet("require 'rubygems'");
        runtime.evalScriptlet("gem 'test-unit'");
        runtime.evalScriptlet("require 'test/unit'");
    }

    private static SuiteResult parseResult(final String json, final String suite) {
        final SuiteResult result = new SuiteResult();
        result.suite = suite;
        result.ran = intField(json, "ran");
        result.passed = intField(json, "passed");
        result.failed = intField(json, "failure_count");
        if (result.failed == 0) {
            result.failed = intField(json, "failed");
        }
        result.skipped = intField(json, "skipped");
        result.assertions = intField(json, "assertions");
        result.failures = splitField(json, "failures");
        result.knownDropSkips = splitField(json, "known_drop_skips");
        result.artifactSkips = splitField(json, "artifact_skips");
        result.nativeOmissions = splitField(json, "native_omissions");
        result.harnessFindings = splitField(json, "harness_findings");
        result.knownDropSkipCount = intField(json, "known_drop_skips_count");
        result.artifactSkipCount = intField(json, "artifact_skips_count");
        result.nativeOmissionCount = intField(json, "native_omissions_count");
        if (result.knownDropSkipCount == 0 && result.knownDropSkips.size() > 0) {
            result.knownDropSkipCount = result.knownDropSkips.size();
        }
        if (result.nativeOmissionCount == 0 && result.nativeOmissions.size() > 0) {
            result.nativeOmissionCount = result.nativeOmissions.size();
        }
        if (result.artifactSkipCount == 0 && result.artifactSkips.size() > 0) {
            result.artifactSkipCount = result.artifactSkips.size();
        }
        result.loadError = boolField(json, "load_error");
        if (result.ran == 0 && result.skipped == 0 && !result.loadError) {
            fail("suite " + suite + " did not execute any tests; json=" + json);
        }
        return result;
    }

    private void printSummary() {
        System.out.println();
        System.out.println("FIPS Ruby coverage summary (designated set: bc-fips 2.0.1, " +
                "bcpkix-fips 2.0.7, bctls-fips 2.0.22, bcutil-fips 2.0.5):");
        for (SuiteResult result : suiteResults.values()) {
            System.out.println(formatSuiteLine(result));
        }
    }

    private static String formatSuiteLine(final SuiteResult result) {
        final StringBuilder line = new StringBuilder();
        line.append(String.format("suite=%s ran=%d passed=%d failed=%d",
                result.suite, result.ran, result.passed, result.failed));
        if (result.knownDropSkipCount > 0) {
            line.append(" known_drop_skips=").append(result.knownDropSkipCount)
                    .append(" (").append(String.join("; ", result.knownDropSkips)).append(')');
        }
        if (result.artifactSkipCount > 0) {
            line.append(" artifact_skips=").append(result.artifactSkipCount)
                    .append(" (").append(String.join("; ", result.artifactSkips)).append(')');
        }
        if (result.nativeOmissionCount > 0) {
            line.append(" native_omissions=").append(result.nativeOmissionCount)
                    .append(" (").append(String.join("; ", result.nativeOmissions)).append(')');
        }
        if (result.harnessFindings.size() > 0) {
            line.append(" harness_findings=").append(result.harnessFindings.size())
                    .append(" (").append(String.join("; ", result.harnessFindings)).append(')');
        }
        return line.toString();
    }

    private static List<String> truncate(final List<String> items, final int max) {
        if (items.size() <= max) return items;
        final List<String> out = new ArrayList<>(items.subList(0, max));
        out.add("... (" + (items.size() - max) + " more)");
        return out;
    }

    private static List<String> list(final String... paths) {
        final List<String> files = new ArrayList<>();
        for (String path : paths) files.add(path);
        return files;
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

    private static boolean boolField(final String json, final String field) {
        final String marker = "\"" + field + "\":";
        final int start = json.indexOf(marker);
        if (start < 0) return false;
        return json.indexOf("true", start + marker.length()) >= 0 &&
                json.indexOf("true", start + marker.length()) < start + marker.length() + 6;
    }

    private static List<String> splitField(final String json, final String field) {
        final String value = stringField(json, field);
        if (value.isEmpty()) return Collections.emptyList();
        final List<String> items = new ArrayList<>();
        for (String line : value.split("\n")) {
            if (!line.isEmpty()) items.add(line);
        }
        return items;
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
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(i + 1);
                if (next == 'n') {
                    value.append('\n');
                    i += 2;
                    continue;
                }
                if (next == 'r') {
                    value.append('\r');
                    i += 2;
                    continue;
                }
                if (next == 't') {
                    value.append('\t');
                    i += 2;
                    continue;
                }
                if (next == '"') {
                    value.append('"');
                    i += 2;
                    continue;
                }
                if (next == '\\') {
                    value.append('\\');
                    i += 2;
                    continue;
                }
                value.append(next);
                i += 2;
                continue;
            }
            if (c == '"') break;
            value.append(c);
            i++;
        }
        return value.toString();
    }

    private static List<String> stringArrayField(final String json, final String field) {
        final String marker = "\"" + field + "\":";
        final int start = json.indexOf(marker);
        if (start < 0) return Collections.emptyList();
        final int arrayStart = json.indexOf('[', start);
        final int arrayEnd = json.indexOf(']', arrayStart);
        if (arrayStart < 0 || arrayEnd < 0) return Collections.emptyList();
        final String body = json.substring(arrayStart + 1, arrayEnd).trim();
        if (body.isEmpty()) return Collections.emptyList();
        final List<String> values = new ArrayList<>();
        for (String part : body.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)")) {
            values.add(part.trim().replaceAll("^\"|\"$", "").replace("\\\"", "\""));
        }
        return values;
    }

    private static final class SuiteResult {
        String suite;
        int ran;
        int passed;
        int failed;
        int skipped;
        int assertions;
        boolean loadError;
        List<String> failures = Collections.emptyList();
        List<String> knownDropSkips = Collections.emptyList();
        List<String> artifactSkips = Collections.emptyList();
        List<String> nativeOmissions = Collections.emptyList();
        List<String> harnessFindings = Collections.emptyList();
        int knownDropSkipCount;
        int artifactSkipCount;
        int nativeOmissionCount;
    }
}
