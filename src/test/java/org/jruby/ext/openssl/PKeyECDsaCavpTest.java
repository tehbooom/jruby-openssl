package org.jruby.ext.openssl;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1OutputStream;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Cryptographic known-answer tests for BCInternal.dsaSignAsn1 / dsaVerifyAsn1.
 *
 * <h2>SigVer — verify path (P-256, P-384, P-521)</h2>
 * Three hardcoded (Qx, Qy, msg_hash, r, s) tuples, one per curve.  Each tuple was
 * generated with Python's cryptography library (which is independent of this code)
 * and cross-checked by Python's own verify() before being recorded here.  Passing
 * these tests proves BCInternal.dsaVerifyAsn1 correctly accepts valid signatures and
 * rejects tampered ones across all three supported curves.
 *
 * <h2>SigGen cross-check — sign path (P-256, P-384, P-521)</h2>
 * BCInternal.dsaSignAsn1 produces a signature; that signature is then verified by
 * the JDK's built-in java.security.Signature (SHA{256,384,512}withECDSA), which is
 * completely independent of BCInternal's code path.  This breaks the circularity of
 * round-trips — the sign output is validated by a different verifier, not by
 * BCInternal.dsaVerifyAsn1 itself.
 *
 * <h2>How the msg_hash values were derived</h2>
 * BCInternal receives pre-hashed bytes and passes them directly to ECDSASigner (no
 * additional hashing).  For the SigVer vectors the msg_hash is SHA-N(msg_bytes),
 * matching what the Python signing library hashed internally.  The JDK cross-check
 * uses Signature.initVerify + update(msg_bytes) + verify(sig) so it hashes internally
 * at the same algorithm — no pre-hash needed on the Java side there.
 *
 * <h2>Python cross-check output (recorded for future reference)</h2>
 * <pre>
 * P-256: verify_stored=True  (Python cryptography 42.x, SECP256R1/SHA-256)
 * P-384: verify_stored=True  (Python cryptography 42.x, SECP384R1/SHA-384)
 * P-521: verify_stored=True  (Python cryptography 42.x, SECP521R1/SHA-512)
 * </pre>
 */
public class PKeyECDsaCavpTest {

    // -------------------------------------------------------------------------
    // P-256 / SHA-256 — Python-verified SigVer tuple
    // msg_bytes = "P-256 ECDSA test for jruby-openssl FIPS" (UTF-8)
    // msg_hash  = SHA-256(msg_bytes)
    // -------------------------------------------------------------------------
    private static final String CURVE_256 = "P-256";
    private static final String JCA_SIG_256 = "SHA256withECDSA";
    private static final BigInteger QX_256 = new BigInteger(
            "c49001405bc51da48696d48e303d7f3ddab5f9d0fab85f369445c68ebab81e3b", 16);
    private static final BigInteger QY_256 = new BigInteger(
            "ce1e56ef6c2bb8d1f5b396100476226a33ba1e087f869bd2950d3321b1847318", 16);
    private static final byte[] HASH_256 = fromHex(
            "522a7c8cb4d79e6409559e4e606bbd8f32b9298eba4b87d9cfb6bad5b2c0189b");
    private static final BigInteger R_256 = new BigInteger(
            "4b12ef4ba5a6d0b29068393464c036df3f27e0f55387526e8f4c2239ba2cebc3", 16);
    private static final BigInteger S_256 = new BigInteger(
            "ad1ebbb8cc3dbefc19dc5af5bdb840eee14da5c320be4c327293b35a73985221", 16);
    private static final BigInteger D_256 = new BigInteger(
            "f9eacb361351a9264ece367f96cfbec16f53b1d90e0e9d1e9ebba8e7bb08dcbc", 16);
    private static final byte[] MSG_256 =
            "P-256 ECDSA test for jruby-openssl FIPS".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    // -------------------------------------------------------------------------
    // P-384 / SHA-384 — Python-verified SigVer tuple
    // msg_bytes = "P-384 ECDSA test for jruby-openssl FIPS" (UTF-8)
    // msg_hash  = SHA-384(msg_bytes)
    // -------------------------------------------------------------------------
    private static final String CURVE_384 = "P-384";
    private static final String JCA_SIG_384 = "SHA384withECDSA";
    private static final BigInteger QX_384 = new BigInteger(
            "2adf006a8f183d9a17355db870a4b1cafb79b892a53b97768d0e31876d82ae809fbe45473a0cef0fb0fc4c2dc991f274", 16);
    private static final BigInteger QY_384 = new BigInteger(
            "b97b9315e5ca90d4d8df2533de81e430d6db10082dba8d2015acabd8e130ea371e582cd99cfeaf426516b212f363f48f", 16);
    private static final byte[] HASH_384 = fromHex(
            "3cac6fe132166397b7e9744455effd771f25ada0fcf16543d9f67b5f423d523c6fcbbbe03ad079f0885e4e0363104f62");
    private static final BigInteger R_384 = new BigInteger(
            "f48ae877def565b2e3510301d8caf753fed0e0f4f680ca3f06bdbb0e6b59510f2d5bf3c9d71d56ef30e76a1c16709ba5", 16);
    private static final BigInteger S_384 = new BigInteger(
            "13615462a9ca7915a054a940e24807cc5e339ab4662fa8965465d9917a70ce73ef5886a4bfc4535d07ef2cfe97d59905", 16);
    private static final BigInteger D_384 = new BigInteger(
            "fcebf7b1ddff33edffd782dfb4cb42c1803c7eff0a5623d06dd9e44fc292bd3f7a3fa1bab6ecc3dc5c84bea9a63331b4", 16);
    private static final byte[] MSG_384 =
            "P-384 ECDSA test for jruby-openssl FIPS".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    // -------------------------------------------------------------------------
    // P-521 / SHA-512 — Python-verified SigVer tuple
    // msg_bytes = "P-521 ECDSA test for jruby-openssl FIPS" (UTF-8)
    // msg_hash  = SHA-512(msg_bytes)
    // -------------------------------------------------------------------------
    private static final String CURVE_521 = "P-521";
    private static final String JCA_SIG_521 = "SHA512withECDSA";
    private static final BigInteger QX_521 = new BigInteger(
            "9d69c637ddbc541d99ccf2cf696755316c9972f290b9dc1403d829c761e1cf973ac0070c833eefb68cd1b9aa22144e740a35e7e6a083856cb88d65dd4c21dee948", 16);
    private static final BigInteger QY_521 = new BigInteger(
            "1014d8e171dec3b603b01aa2f1e7d68c7e761b800f691180e1c2f11fa5406fb409a637600601299fcf98f200f3c5b619be13bc5d637b3970624737badaad7b05844", 16);
    private static final byte[] HASH_512 = fromHex(
            "e85ee3446b5421cc24dbff29e7bc8d7e820b8fb099c44e9099f16d5244f89b7f" +
            "037df76afe582d397eb33c45797c3150d1e7298981c193c58b6d74925d00650d");
    private static final BigInteger R_521 = new BigInteger(
            "9fa9e4944ff5decd2f9111a40d56f3c5df29888b5911ec8e5e830112e080edcb7f865b838e806ac2d250b179796231269df943d9d80ba0147944bc4e6b2e02c808", 16);
    private static final BigInteger S_521 = new BigInteger(
            "284ce7fbbf615c3a07184fd8e0571a88769f29ae5bac91bf96b9f5e51477ca8c88d52c41ac30f92658be95774872f9d6ac71ef4b5ac5e88e925d8e1d85897f37d4", 16);
    private static final BigInteger D_521 = new BigInteger(
            "c04c3005ba860bdad6448c7196052246ba20843e90352bc0ad029d6c30feaf8c3484ccd3af6b1adce15b2d91ac63e6fee06c42deab2a044ac9adcefc61bd17f29f", 16);
    private static final byte[] MSG_521 =
            "P-521 ECDSA test for jruby-openssl FIPS".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    // =========================================================================
    // SigVer tests: BCInternal.dsaVerifyAsn1 against Python-verified tuples
    // =========================================================================

    @Test
    public void sigVer_P256_knownGoodAccepted() throws Exception {
        ECPublicKey pub = buildPublicKey("secp256r1", QX_256, QY_256);
        ASN1Sequence seq = toSeq(buildDerSig(R_256, S_256));
        assertTrue(callVerify(pub, CURVE_256, HASH_256, seq),
                "P-256 SigVer: Python-verified vector must be accepted by dsaVerifyAsn1");
    }

    @Test
    public void sigVer_P256_tamperedRRejected() throws Exception {
        ECPublicKey pub = buildPublicKey("secp256r1", QX_256, QY_256);
        ASN1Sequence seq = toSeq(buildDerSig(R_256.xor(BigInteger.ONE), S_256));
        assertFalse(callVerify(pub, CURVE_256, HASH_256, seq),
                "P-256 SigVer: R XOR 1 must be rejected");
    }

    @Test
    public void sigVer_P256_tamperedSRejected() throws Exception {
        ECPublicKey pub = buildPublicKey("secp256r1", QX_256, QY_256);
        ASN1Sequence seq = toSeq(buildDerSig(R_256, S_256.xor(BigInteger.ONE)));
        assertFalse(callVerify(pub, CURVE_256, HASH_256, seq),
                "P-256 SigVer: S XOR 1 must be rejected");
    }

    @Test
    public void sigVer_P384_knownGoodAccepted() throws Exception {
        ECPublicKey pub = buildPublicKey("secp384r1", QX_384, QY_384);
        ASN1Sequence seq = toSeq(buildDerSig(R_384, S_384));
        assertTrue(callVerify(pub, CURVE_384, HASH_384, seq),
                "P-384 SigVer: Python-verified vector must be accepted by dsaVerifyAsn1");
    }

    @Test
    public void sigVer_P384_tamperedRRejected() throws Exception {
        ECPublicKey pub = buildPublicKey("secp384r1", QX_384, QY_384);
        ASN1Sequence seq = toSeq(buildDerSig(R_384.xor(BigInteger.ONE), S_384));
        assertFalse(callVerify(pub, CURVE_384, HASH_384, seq),
                "P-384 SigVer: R XOR 1 must be rejected");
    }

    @Test
    public void sigVer_P384_tamperedSRejected() throws Exception {
        ECPublicKey pub = buildPublicKey("secp384r1", QX_384, QY_384);
        ASN1Sequence seq = toSeq(buildDerSig(R_384, S_384.xor(BigInteger.ONE)));
        assertFalse(callVerify(pub, CURVE_384, HASH_384, seq),
                "P-384 SigVer: S XOR 1 must be rejected");
    }

    @Test
    public void sigVer_P521_knownGoodAccepted() throws Exception {
        ECPublicKey pub = buildPublicKey("secp521r1", QX_521, QY_521);
        ASN1Sequence seq = toSeq(buildDerSig(R_521, S_521));
        assertTrue(callVerify(pub, CURVE_521, HASH_512, seq),
                "P-521 SigVer: Python-verified vector must be accepted by dsaVerifyAsn1");
    }

    @Test
    public void sigVer_P521_tamperedRRejected() throws Exception {
        ECPublicKey pub = buildPublicKey("secp521r1", QX_521, QY_521);
        ASN1Sequence seq = toSeq(buildDerSig(R_521.xor(BigInteger.ONE), S_521));
        assertFalse(callVerify(pub, CURVE_521, HASH_512, seq),
                "P-521 SigVer: R XOR 1 must be rejected");
    }

    @Test
    public void sigVer_P521_tamperedSRejected() throws Exception {
        ECPublicKey pub = buildPublicKey("secp521r1", QX_521, QY_521);
        ASN1Sequence seq = toSeq(buildDerSig(R_521, S_521.xor(BigInteger.ONE)));
        assertFalse(callVerify(pub, CURVE_521, HASH_512, seq),
                "P-521 SigVer: S XOR 1 must be rejected");
    }

    // =========================================================================
    // SigGen cross-check: BCInternal.dsaSignAsn1 output verified by JDK Signature
    //
    // BCInternal.dsaSignAsn1 takes pre-hashed bytes and signs them with ECDSASigner.
    // The JDK's Signature.getInstance("SHA256withECDSA") hashes the raw message
    // internally before verifying.  Because ECDSASigner in BCInternal is called with
    // the same bytes that SHA-N(msg) produces, and JDK verifies SHA-N(msg) internally,
    // the two paths agree on what was signed — making JDK an independent verifier of
    // BCInternal's sign output.
    // =========================================================================

    @Test
    public void sigGen_P256_jdkVerifiesOutput() throws Exception {
        ECPrivateKey priv = buildPrivateKey("secp256r1", D_256, QX_256, QY_256);
        ECPublicKey  pub  = buildPublicKey("secp256r1", QX_256, QY_256);

        // BCInternal signs the pre-hashed bytes (SHA-256 of MSG_256)
        byte[] sig = callSign(priv, CURVE_256, HASH_256);

        // JDK Signature verifies against the raw message, hashing internally
        Signature jdkSig = Signature.getInstance(JCA_SIG_256);
        jdkSig.initVerify(pub);
        jdkSig.update(MSG_256);
        assertTrue(jdkSig.verify(sig),
                "P-256: signature from BCInternal.dsaSignAsn1 must be accepted by JDK SHA256withECDSA");
    }

    @Test
    public void sigGen_P384_jdkVerifiesOutput() throws Exception {
        ECPrivateKey priv = buildPrivateKey("secp384r1", D_384, QX_384, QY_384);
        ECPublicKey  pub  = buildPublicKey("secp384r1", QX_384, QY_384);

        byte[] sig = callSign(priv, CURVE_384, HASH_384);

        Signature jdkSig = Signature.getInstance(JCA_SIG_384);
        jdkSig.initVerify(pub);
        jdkSig.update(MSG_384);
        assertTrue(jdkSig.verify(sig),
                "P-384: signature from BCInternal.dsaSignAsn1 must be accepted by JDK SHA384withECDSA");
    }

    @Test
    public void sigGen_P521_jdkVerifiesOutput() throws Exception {
        ECPrivateKey priv = buildPrivateKey("secp521r1", D_521, QX_521, QY_521);
        ECPublicKey  pub  = buildPublicKey("secp521r1", QX_521, QY_521);

        byte[] sig = callSign(priv, CURVE_521, HASH_512);

        Signature jdkSig = Signature.getInstance(JCA_SIG_521);
        jdkSig.initVerify(pub);
        jdkSig.update(MSG_521);
        assertTrue(jdkSig.verify(sig),
                "P-521: signature from BCInternal.dsaSignAsn1 must be accepted by JDK SHA512withECDSA");
    }

    // =========================================================================
    // helpers
    // =========================================================================

    private static ECParameterSpec spec(String stdName) throws Exception {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec(stdName));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    private static ECPublicKey buildPublicKey(String curve, BigInteger x, BigInteger y) throws Exception {
        return (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec(curve)));
    }

    private static ECPrivateKey buildPrivateKey(String curve, BigInteger d,
                                                BigInteger qx, BigInteger qy) throws Exception {
        return (ECPrivateKey) KeyFactory.getInstance("EC")
                .generatePrivate(new ECPrivateKeySpec(d, spec(curve)));
    }

    private static byte[] buildDerSig(BigInteger r, BigInteger s) throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ASN1OutputStream out = ASN1OutputStream.create(buf, ASN1Encoding.DER);
        out.writeObject(new DERSequence(v));
        out.close();
        return buf.toByteArray();
    }

    private static ASN1Sequence toSeq(byte[] der) throws Exception {
        return (ASN1Sequence) new ASN1InputStream(der).readObject();
    }

    private static byte[] callSign(ECPrivateKey priv, String curve, byte[] hash) throws Exception {
        Class<?> bc = Class.forName("org.jruby.ext.openssl.PKeyEC$BCInternal");
        java.lang.reflect.Method m = bc.getDeclaredMethod(
                "dsaSignAsn1", ECPrivateKey.class, String.class, byte[].class);
        m.setAccessible(true);
        return (byte[]) m.invoke(null, priv, curve, hash);
    }

    private static boolean callVerify(ECPublicKey pub, String curve,
                                       byte[] hash, ASN1Sequence seq) throws Exception {
        Class<?> bc = Class.forName("org.jruby.ext.openssl.PKeyEC$BCInternal");
        java.lang.reflect.Method m = bc.getDeclaredMethod(
                "dsaVerifyAsn1", ECPublicKey.class, String.class, byte[].class, ASN1Sequence.class);
        m.setAccessible(true);
        return (boolean) m.invoke(null, pub, curve, hash, seq);
    }

    private static byte[] fromHex(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                             + Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return data;
    }
}
