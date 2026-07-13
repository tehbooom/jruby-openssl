package org.jruby.ext.openssl;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression guard for BCInternal.getDomainParametersFromName.
 *
 * getDomainParametersFromName replaced an ECNamedCurveSpec instanceof check with an
 * AlgorithmParameters.getInstance("EC") lookup so it works under both BC and bc-fips.
 * If the detection is broken it produces explicit EC parameters instead of a named OID —
 * a silent interoperability break that shows up only at key-exchange time.
 *
 * These tests call BCInternal.toPrivateKeyInfo directly — the same path taken by
 * private_to_der → toPrivateKeyInfo → getDomainParametersFromName — and confirm the
 * EC AlgorithmIdentifier parameters are a named OID, not explicit params.
 */
public class PKeyECNamedCurveEncodingTest {

    @Test
    public void p256EncodesAsNamedOid() throws Exception {
        assertNamedOidEncoding("secp256r1", "1.2.840.10045.3.1.7");
    }

    @Test
    public void p384EncodesAsNamedOid() throws Exception {
        assertNamedOidEncoding("secp384r1", "1.3.132.0.34");
    }

    @Test
    public void p521EncodesAsNamedOid() throws Exception {
        assertNamedOidEncoding("secp521r1", "1.3.132.0.35");
    }

    private static void assertNamedOidEncoding(String curveName, String expectedOid) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curveName));
        KeyPair kp = kpg.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) kp.getPublic();

        // Call BCInternal.toPrivateKeyInfo via reflection — this is the exact path taken by
        // private_to_der: private_to_der → toPrivateKeyInfo → getDomainParametersFromName.
        // Using privateKey.getEncoded() would exercise the JDK's own encoding, not ours.
        byte[] encoded = callToPrivateKeyInfo(privateKey, publicKey);
        assertNotNull(encoded, "encoded key must not be null");

        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(encoded);
        assertEquals(
            X9ObjectIdentifiers.id_ecPublicKey,
            pki.getPrivateKeyAlgorithm().getAlgorithm(),
            "algorithm OID must be id-ecPublicKey"
        );

        X962Parameters params = X962Parameters.getInstance(pki.getPrivateKeyAlgorithm().getParameters());
        assertFalse(params.isImplicitlyCA(), curveName + " must not be implicitlyCA");
        assertTrue(params.isNamedCurve(),
            curveName + " must encode as named OID, not explicit params — " +
            "getDomainParametersFromName detection is broken");

        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) params.getParameters();
        assertEquals(
            new ASN1ObjectIdentifier(expectedOid),
            oid,
            curveName + " must use OID " + expectedOid
        );
    }

    private static byte[] callToPrivateKeyInfo(ECPrivateKey priv, ECPublicKey pub) throws Exception {
        Class<?> bc = Class.forName("org.jruby.ext.openssl.PKeyEC$BCInternal");
        Method m = bc.getDeclaredMethod("toPrivateKeyInfo", ECPrivateKey.class, ECPublicKey.class);
        m.setAccessible(true);
        Object pki = m.invoke(null, priv, pub);
        Method enc = pki.getClass().getMethod("getEncoded", String.class);
        return (byte[]) enc.invoke(pki, ASN1Encoding.DER);
    }
}
