package org.jruby.ext.openssl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;

import org.jruby.Ruby;
import org.jruby.RubyString;
import org.jruby.exceptions.RaiseException;
import org.jruby.util.ByteList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Group 4 FIPS behavior via actual OpenSSL Ruby entry points.
 */
public class Group4BehaviorTest {

    private static final String EXPECTED_WITH_SALT = "be90a86901bcd1cc93993c7e3ac52a886544fa0bdf2950b8";
    private static final String EXPECTED_EMPTY_SALT = "bd27c3e3558945b4bc5eb0d89f197efffc96b52be19266d9";
    private static final String RED_GET_BYTES_HEX = "58edfb03303803dd87c8f6f9b8cae66ce59523940fad62d1";

    @BeforeAll
    static void enableFipsProfile() throws Exception {
        try {
            Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            assumeTrue(false, "Group 4 behavior vectors require the FIPS-only classpath");
        }
        catch (ClassNotFoundException expected) {
            // Designated FIPS profile.
        }
        FipsTestEnvironment.registerConfiguredProviders();
    }

    @AfterAll
    static void disableFipsProfile() {
        FipsTestEnvironment.removeConfiguredProviders();
    }

    @Test
    void redEvidencePreFixFipsSecretKeyFactoryEffectivelyUsedUtf8Password() throws Exception {
        final byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);
        final javax.crypto.Mac mac = SecurityHelper.getMac("HmacSHA1");

        mac.init(new SimpleSecretKey("HmacSHA1", new byte[] {(byte) 0xff}));
        final String rawPassword = bytesToHex(PKCS5.deriveKey(mac, salt, 42, 24));

        mac.init(new SimpleSecretKey("HmacSHA1", new byte[] {(byte) 0xc3, (byte) 0xbf}));
        final String utf8Expanded = bytesToHex(PKCS5.deriveKey(mac, salt, 42, 24));

        assertEquals(EXPECTED_WITH_SALT, rawPassword);
        assertEquals(RED_GET_BYTES_HEX, utf8Expanded,
                "pre-fix FIPS PBEKeySpec char path effectively PBKDF2'd UTF-8 C3 BF");
        assertNotEquals(rawPassword, utf8Expanded);
    }

    @Test
    void redEvidenceRubyStringGetBytesOnBinary0xff() {
        final Ruby runtime = Ruby.newInstance();
        try {
            final RubyString pass = (RubyString) runtime.evalScriptlet("\"\\xFF\".b");
            final byte[] viaGetBytes = pass.getBytes();
            final ByteList raw = pass.getByteList();
            final byte[] viaByteList = PKCS5.rubyStringBytes(pass);

            assertArrayEquals(new byte[] {(byte) 0xff}, viaByteList, "ByteList preserves raw 0xff");
            assertArrayEquals(viaGetBytes, viaByteList,
                    "JRuby getBytes matches ByteList for ASCII-8BIT on this runtime");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void pbkdf2HmacSha1PreservesBinaryPasswordThroughRubyApi() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final String withSalt = runtime.evalScriptlet(
                    "pass = \"\\xFF\".b\n" +
                    "OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass, 'salt', 42, 24).unpack1('H*')"
            ).toString();
            final String emptySalt = runtime.evalScriptlet(
                    "pass = \"\\xFF\".b\n" +
                    "OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass, '', 42, 24).unpack1('H*')"
            ).toString();

            assertEquals(EXPECTED_WITH_SALT, withSalt);
            assertEquals(EXPECTED_EMPTY_SALT, emptySalt);
            assertNotEquals(RED_GET_BYTES_HEX, withSalt);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void pbkdf2HmacSha1EmptySaltThroughRubyApi() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final String actual = runtime.evalScriptlet(
                    "OpenSSL::PKCS5.pbkdf2_hmac_sha1(' ', '', 16, 24).unpack1('H*')"
            ).toString();
            assertEquals("811be946d86f70a69df43d0958138244f7f37fc86146522b", actual);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void redEvidencePbeKeySpecRejectsEmptySalt() {
        assertThrows(IllegalArgumentException.class, () ->
                new javax.crypto.spec.PBEKeySpec(
                        new char[] {'p'}, new byte[0], 16, 24 * 8));
    }

    @Test
    void cipherCiphersOnlyAdvertisesInstantiableNamesThroughRubyApi() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            runtime.evalScriptlet(
                    "OpenSSL::Cipher.ciphers.each do |name|\n" +
                    "  next if name.end_with?('wrap')\n" +
                    "  OpenSSL::Cipher.new(name)\n" +
                    "end\n" +
                    "if OpenSSL::Cipher.ciphers.any? { |n| n =~ /CFB1/i }\n" +
                    "  raise 'advertised CFB1'\n" +
                    "end\n" +
                    "if OpenSSL::Cipher.ciphers.any? { |n| n =~ /PCBC/i }\n" +
                    "  raise 'advertised PCBC'\n" +
                    "end\n" +
                    "real = OpenSSL::Cipher.new('DES-EDE-CFB').name\n" +
                    "raise \"bad DES-EDE-CFB real name: #{real}\" unless real == 'DES-EDE-CFB'\n");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void desEdeCfbUsesNoPaddingSemanticsThroughRubyApi() throws Exception {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final String result = runtime.evalScriptlet(
                    "c = OpenSSL::Cipher.new('DES-EDE-CFB')\n" +
                    "[c.name, c.key_len, c.iv_len].join(':')"
            ).toString();
            assertEquals("DES-EDE-CFB:16:8", result);
            assertFalse(Cipher.Algorithm.getRealName("DES-EDE-CFB").contains("PKCS5Padding"));
            assertEquals("BCFIPS",
                    SecurityHelper.getCipher("DESede/CFB/NoPadding").getProvider().getName());
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void twoKeyTdeaEncryptionRejectedUnderFipsThroughRubyApi() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final RaiseException error = assertThrows(RaiseException.class, () ->
                    runtime.evalScriptlet(
                            "c = OpenSSL::Cipher.new('DES-EDE-CFB')\n" +
                            "c.encrypt\n" +
                            "c.key = \"\\0\" * 16\n" +
                            "c.iv = \"\\0\" * 8\n" +
                            "c.update('JPMNT')"
                    ));
            assertTrue(error.getMessage().contains("two-key TDEA encryption is disallowed"),
                    "unexpected: " + error.getMessage());
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void twoKeyTdeaDecryptionAllowedUnderFipsThroughRubyApi() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            // Legacy decrypt path: ciphertext from non-FIPS BC (MRI-compatible vector).
            final String plaintext = runtime.evalScriptlet(
                    "key = \"\\0\\0\\0\\0\\0\\0\\0\\0\" * 3\n" +
                    "iv = \"\\0\\0\\0\\0\\0\\0\\0\\0\"\n" +
                    "c = OpenSSL::Cipher.new('DES-EDE-CFB')\n" +
                    "c.decrypt\n" +
                    "c.key = key\n" +
                    "c.iv = iv\n" +
                    "c.pkcs5_keyivgen(key, iv)\n" +
                    "ct = \"l\\x02?\\x16\\x1A\"\n" +
                    "c.update(ct) + c.final"
            ).toString();
            assertEquals("JPMNT", plaintext);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void threeKeyTdeaEncryptionAllowedByProviderUnderFipsThroughRubyApi() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final String ciphertext = runtime.evalScriptlet(
                    "key = \"\\x1F\\xFF&\\xA4k\\x8F^\\xC80\\txq'S\\x93\\xD2\\xE3A\\xEDT\\xDCs\\xFD<=G\\a\\x8F=\\x8FhE\"\n" +
                    "iv = \"\\0\" * 8\n" +
                    "c = OpenSSL::Cipher.new('DES-EDE3-CFB')\n" +
                    "c.encrypt\n" +
                    "c.key = key\n" +
                    "c.iv = iv\n" +
                    "(c.update('JPMNT') + c.final).unpack1('H*')"
            ).toString();
            assertEquals("1b6dcd5321", ciphertext,
                    "24-byte three-key TDEA encryption remains provider-allowed under FIPS");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void pkcs5RubySuitePassesUnderFips() {
        runRubySuite("pkcs5", "src/test/ruby/pkcs5/test_pbkdf2.rb");
    }

    @Test
    void cipherRubySuitePassesUnderFips() {
        runRubySuite("cipher", "src/test/ruby/test_cipher.rb");
    }

    private static void runRubySuite(final String suite, final String file) {
        final Ruby runtime = Ruby.newInstance();
        try {
            bootstrapRuby(runtime);
            runtime.evalScriptlet("ENV['JRUBY_OPENSSL_FIPS_TESTS'] = 'true'");
            runtime.evalScriptlet("ENV['FIPS_RUBY_SUITE'] = '" + suite + "'");
            runtime.evalScriptlet("ENV['FIPS_RUBY_FILES'] = '" + file + "'");
            runtime.evalScriptlet("$fips_harness_findings = []");
            runtime.evalScriptlet(
                    "load '" + new java.io.File("src/test/ruby/fips/run_suite.rb").getAbsolutePath() + "'");
            final String json = runtime.evalScriptlet("$fips_ruby_result").toString();
            final int failedCount;
            int parsedFailed = intField(json, "failure_count");
            if (parsedFailed == 0) parsedFailed = intField(json, "failed");
            failedCount = parsedFailed;
            assertEquals(0, failedCount, suite + " suite failures: " + stringField(json, "failures"));
        }
        catch (RaiseException e) {
            throw new AssertionError(suite + " harness error: " + e.getMessage(), e);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    private static void bootstrapRuby(final Ruby runtime) {
        final String lib = new java.io.File("lib").getAbsolutePath();
        final String testRuby = new java.io.File("src/test/ruby").getAbsolutePath();
        runtime.evalScriptlet("$LOAD_PATH.unshift '" + lib + "'");
        runtime.evalScriptlet("$LOAD_PATH.unshift '" + testRuby + "'");
        runtime.evalScriptlet("require 'rubygems'");
        runtime.evalScriptlet("gem 'test-unit'");
        runtime.evalScriptlet("require 'test/unit'");
        OpenSSL.createOpenSSL(runtime);
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

    private static String bytesToHex(final byte[] bytes) {
        final StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (final byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
