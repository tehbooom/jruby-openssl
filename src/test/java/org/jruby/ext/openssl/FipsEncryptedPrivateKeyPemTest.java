package org.jruby.ext.openssl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

import org.jruby.Ruby;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Group 1 FIPS PEM behavior: PBES2 PKCS#8 encrypted keys load under FIPS;
 * legacy Proc-Type MD5 EVP_BytesToKey encrypted PEM is rejected without
 * bcprov-internal ClassNotFoundException.
 */
public class FipsEncryptedPrivateKeyPemTest {

    private static final Path PEM_FIXTURES =
            Paths.get("src/test/resources/fips/pem");
    private static final char[] PBES2_PASSWORD = "group1pbes2".toCharArray();

    private static final String LEGACY_RSA_ENCRYPTED_PEM = ""
            + "-----BEGIN RSA PRIVATE KEY-----\n"
            + "Proc-Type: 4,ENCRYPTED\n"
            + "DEK-Info: AES-128-CBC,733F5302505B34701FC41F5C0746E4C0\n"
            + "\n"
            + "zgJniZZQfvv8TFx3LzV6zhAQVayvQVZlAYqFq2yWbbxzF7C+IBhKQle9IhUQ9j/y\n"
            + "/jkvol550LS8vZ7TX5WxyDLe12cdqzEvpR6jf3NbxiNysOCxwG4ErhaZGP+krcoB\n"
            + "ObuL0nvls/+3myy5reKEyy22+0GvTDjaChfr+FwJjXMG+IBCLscYdgZC1LQL6oAn\n"
            + "9xY5DH3W7BW4wR5ttxvtN32TkfVQh8xi3jrLrduUh+hV8DTiAiLIhv0Vykwhep2p\n"
            + "WZA+7qbrYaYM8GLLgLrb6LfBoxeNxAEKiTpl1quFkm+Hk1dKq0EhVnxHf92x0zVF\n"
            + "jRGZxAMNcrlCoE4f5XK45epVZSZvihdo1k73GPbp84aZ5P/xlO4OwZ3i4uCQXynl\n"
            + "jE9c+I+4rRWKyPz9gkkqo0+teJL8ifeKt/3ab6FcdA0aArynqmsKJMktxmNu83We\n"
            + "YVGEHZPeOlyOQqPvZqWsLnXQUfg54OkbuV4/4mWSIzxFXdFy/AekSeJugpswMXqn\n"
            + "oNck4qySNyfnlyelppXyWWwDfVus9CVAGZmJQaJExHMT/rQFRVchlmY0Ddr5O264\n"
            + "gcjv90o1NBOc2fNcqjivuoX7ROqys4K/YdNQ1HhQ7usJghADNOtuLI8ZqMh9akXD\n"
            + "Eqp6Ne97wq1NiJj0nt3SJlzTnOyTjzrTe0Y+atPkVKp7SsjkATMI9JdhXwGhWd7a\n"
            + "qFVl0owZiDasgEhyG2K5L6r+yaJLYkPVXZYC/wtWC3NEchnDWZGQcXzB4xROCQkD\n"
            + "OlWNYDkPiZioeFkA3/fTMvG4moB2Pp9Q4GU5fJ6k43Ccu1up8dX/LumZb4ecg5/x\n"
            + "-----END RSA PRIVATE KEY-----\n";

    private static final String LEGACY_EC_ENCRYPTED_PEM = ""
            + "-----BEGIN EC PRIVATE KEY-----\n"
            + "Proc-Type: 4,ENCRYPTED\n"
            + "DEK-Info: AES-128-CBC,85743EB6FAC9EA76BF99D9328AFD1A66\n"
            + "\n"
            + "nhsP1NHxb53aeZdzUe9umKKyr+OIwQq67eP0ONM6E1vFTIcjkDcFLR6PhPFufF4m\n"
            + "y7E2HF+9uT1KPQhlE+D63i1m1Mvez6PWfNM34iOQp2vEhaoHHKlR3c43lLyzaZDI\n"
            + "0/dGSU5SzFG+iT9iFXCwCvv+bxyegkBOyALFje1NAsM=\n"
            + "-----END EC PRIVATE KEY-----\n";

    @BeforeAll
    static void enableFipsProfile() throws Exception {
        try {
            Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            assumeTrue(false, "Group 1 PEM vectors require the FIPS-only classpath");
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
    void pbes2EncryptedRsaPemLoadsViaPemInputOutput() throws Exception {
        final String pem = fixture("rsa-pbes2.pem");
        final KeyPair pair = PEMInputOutput.readPrivateKey(new StringReader(pem), PBES2_PASSWORD);
        assertNotNull(pair);
        assertNotNull(pair.getPrivate());
        assertTrue(pair.getPrivate() instanceof RSAPrivateCrtKey);
        assertEquals(2048, ((RSAPrivateCrtKey) pair.getPrivate()).getModulus().bitLength());
        System.out.println("PBES2 RSA ENCRYPTED PRIVATE KEY loaded via PEMInputOutput under FIPS");
    }

    @Test
    void pbes2EncryptedEcPemLoadsViaPemInputOutput() throws Exception {
        final String pem = fixture("ec-pbes2.pem");
        final KeyPair pair = PEMInputOutput.readPrivateKey(new StringReader(pem), PBES2_PASSWORD);
        assertNotNull(pair);
        assertNotNull(pair.getPrivate());
        assertTrue(pair.getPrivate() instanceof ECPrivateKey);
        final ECPrivateKey ec = (ECPrivateKey) pair.getPrivate();
        assertEquals(256, ec.getParams().getOrder().bitLength());
        System.out.println("PBES2 EC ENCRYPTED PRIVATE KEY loaded via PEMInputOutput under FIPS");
    }

    @Test
    void pbes2EncryptedDsaPemDecryptsBeforeFipsDeriveYLimit() throws Exception {
        final IOException error = assertThrows(IOException.class, () ->
                PEMInputOutput.readPrivateKey(
                        new StringReader(fixture("dsa-pbes2.pem")), PBES2_PASSWORD));
        assertTrue(error.getMessage().contains("DSA public key is required") ||
                        (error.getCause() != null &&
                                error.getCause().getMessage().contains("deriving y from x")),
                "PBES2 DSA decrypt must reach the shared FIPS derive-y gate, not fail earlier: "
                        + error.getMessage());
        System.out.println("PBES2 DSA ENCRYPTED PRIVATE KEY decrypted; FIPS derive-y gate: "
                + error.getMessage());
    }

    @Test
    void pbes2EncryptedRsaPemLoadsViaRubyApi() throws Exception {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final String pem = fixture("rsa-pbes2.pem");
            runtime.evalScriptlet("$group1_rsa_pem = " + rubyStringLiteral(pem));
            runtime.evalScriptlet(
                    "$group1_rsa = OpenSSL::PKey::RSA.new($group1_rsa_pem, 'group1pbes2')");
            final int bits = runtime.evalScriptlet("$group1_rsa.n.num_bits").convertToInteger().getIntValue();
            assertEquals(2048, bits);
            System.out.println("PBES2 RSA ENCRYPTED PRIVATE KEY loaded via Ruby API under FIPS");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void pbes2EncryptedEcPemLoadsViaRubyApi() throws Exception {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final String pem = fixture("ec-pbes2.pem");
            runtime.evalScriptlet("$group1_ec_pem = " + rubyStringLiteral(pem));
            runtime.evalScriptlet(
                    "$group1_ec = OpenSSL::PKey::EC.new($group1_ec_pem, 'group1pbes2')");
            final String curve = runtime.evalScriptlet(
                    "$group1_ec.group.curve_name").convertToString().toString();
            assertEquals("prime256v1", curve);
            System.out.println("PBES2 EC ENCRYPTED PRIVATE KEY loaded via Ruby API under FIPS");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void legacyMd5EncryptedRsaPemRejectedWithoutClassNotFound() {
        assertLegacyEncryptedPemRejected(
                "OpenSSL::PKey::RSA.new($legacy_rsa_pem, 'abcdef')",
                LEGACY_RSA_ENCRYPTED_PEM,
                "$legacy_rsa_pem");
    }

    @Test
    void legacyMd5EncryptedEcPemRejectedWithoutClassNotFound() {
        assertLegacyEncryptedPemRejected(
                "OpenSSL::PKey::EC.new($legacy_ec_pem, 'abcdef')",
                LEGACY_EC_ENCRYPTED_PEM,
                "$legacy_ec_pem");
    }

    @Test
    void legacyMd5EncryptedPemRejectedAtJavaLayer() {
        final IOException error = assertThrows(IOException.class, () ->
                PEMInputOutput.readPrivateKey(
                        new StringReader(LEGACY_RSA_ENCRYPTED_PEM), "abcdef".toCharArray()));
        assertTrue(error.getMessage().contains("MD5 EVP_BytesToKey"),
                "expected FIPS legacy PEM rejection, got: " + error.getMessage());
        assertTrue(error.getCause() == null ||
                        !error.getCause().getClass().getName().contains("ClassNotFoundException"),
                "legacy PEM rejection must not surface ClassNotFoundException");
        System.out.println("legacy RSA Proc-Type PEM rejected at Java layer: " + error.getMessage());
    }

    private static void assertLegacyEncryptedPemRejected(final String call,
            final String pem, final String var) {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            runtime.evalScriptlet(var + " = " + rubyStringLiteral(pem));
            final RaiseException error = assertThrows(RaiseException.class,
                    () -> runtime.evalScriptlet(call));
            final String message = error.getException().getMessage().toString();
            assertTrue(message.contains("Neither PUB key nor PRIV key"), message);
            System.out.println("legacy encrypted PEM Ruby rejection: " + message);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    private static String fixture(final String name) throws IOException {
        return new String(Files.readAllBytes(PEM_FIXTURES.resolve(name)), StandardCharsets.US_ASCII);
    }

    private static String rubyStringLiteral(final String value) {
        final StringBuilder quoted = new StringBuilder(value.length() + 16);
        quoted.append('"');
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            switch (c) {
                case '\\': quoted.append("\\\\"); break;
                case '"': quoted.append("\\\""); break;
                case '\n': quoted.append("\\n"); break;
                case '\r': quoted.append("\\r"); break;
                default: quoted.append(c);
            }
        }
        quoted.append('"');
        return quoted.toString();
    }
}
