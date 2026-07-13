package org.jruby.ext.openssl;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that the JCA primitives used by PKeyEC and PKeyRSA work correctly
 * when BouncyCastle FIPS (BCFIPS) is the active provider and no non-FIPS BC
 * jar is present on the classpath. Must run under the fips-tests Maven profile
 * so that non-FIPS BC jars are excluded from the Surefire classpath.
 */
public class FipsCoverageTest {

    private static Provider fipsProvider;

    @BeforeAll
    static void registerFipsProvider() throws Exception {
        // Hard fail if non-FIPS BouncyCastle is loadable — that would mask the
        // failures these tests exist to catch. Run via: mvn test -Pfips-tests -Dfips.jar=...
        assertNull(
            Security.getProvider("BC"),
            "Non-FIPS BouncyCastle provider 'BC' must not be registered. " +
            "Run this test class via the fips-tests Maven profile which excludes non-FIPS BC jars."
        );
        try {
            Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            fail("org.bouncycastle.jce.provider.BouncyCastleProvider must not be loadable. " +
                 "Non-FIPS BC is on the classpath — run via the fips-tests Maven profile.");
        } catch (ClassNotFoundException expected) {
            // correct: non-FIPS BC is absent
        }

        Provider p = (Provider) Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider")
                .getDeclaredConstructor()
                .newInstance();
        Security.insertProviderAt(p, 1);
        fipsProvider = p;
    }

    @AfterAll
    static void removeFipsProvider() {
        if (fipsProvider != null) {
            Security.removeProvider(fipsProvider.getName());
        }
    }

    @Test
    void ecKeygenP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", fipsProvider);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();
        assertNotNull(kp);
        assertInstanceOf(ECPublicKey.class, kp.getPublic());
        assertInstanceOf(ECPrivateKey.class, kp.getPrivate());
    }

    @Test
    void ecKeygenP384() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", fipsProvider);
        kpg.initialize(new ECGenParameterSpec("P-384"));
        KeyPair kp = kpg.generateKeyPair();
        assertNotNull(kp);
        assertInstanceOf(ECPublicKey.class, kp.getPublic());
        assertInstanceOf(ECPrivateKey.class, kp.getPrivate());
    }

    @Test
    void ecKeygenP521() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", fipsProvider);
        kpg.initialize(new ECGenParameterSpec("P-521"));
        KeyPair kp = kpg.generateKeyPair();
        assertNotNull(kp);
        assertInstanceOf(ECPublicKey.class, kp.getPublic());
        assertInstanceOf(ECPrivateKey.class, kp.getPrivate());
    }

    @Test
    void ecKeyFactoryRoundTripFromDer() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", fipsProvider);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        byte[] encoded = kp.getPublic().getEncoded();
        KeyFactory kf = KeyFactory.getInstance("EC", fipsProvider);
        ECPublicKey decoded = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));

        assertArrayEquals(encoded, decoded.getEncoded());
    }

    @Test
    void ecdhSharedSecretBothSidesMatch() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", fipsProvider);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair aliceKp = kpg.generateKeyPair();
        KeyPair bobKp = kpg.generateKeyPair();

        KeyAgreement aliceKa = KeyAgreement.getInstance("ECDH", fipsProvider);
        aliceKa.init(aliceKp.getPrivate());
        aliceKa.doPhase(bobKp.getPublic(), true);
        byte[] aliceSecret = aliceKa.generateSecret();

        KeyAgreement bobKa = KeyAgreement.getInstance("ECDH", fipsProvider);
        bobKa.init(bobKp.getPrivate());
        bobKa.doPhase(aliceKp.getPublic(), true);
        byte[] bobSecret = bobKa.generateSecret();

        assertArrayEquals(aliceSecret, bobSecret);
    }

    @Test
    void rsaKeygen2048() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", fipsProvider);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        assertNotNull(kp);
        assertNotNull(kp.getPublic());
        assertNotNull(kp.getPrivate());
    }

    @Test
    void rsaOaepEncryptDecryptRoundTrip() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", fipsProvider);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] plaintext = new byte[]{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };

        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", fipsProvider);
        enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] ciphertext = enc.doFinal(plaintext);

        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", fipsProvider);
        dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] recovered = dec.doFinal(ciphertext);

        assertArrayEquals(plaintext, recovered);
    }
}
