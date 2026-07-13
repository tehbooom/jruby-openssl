package org.jruby.ext.openssl;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Known-answer tests for BCInternal point arithmetic: pointMul, pointAdd, pointMulTwo, decodePoint.
 *
 * <h2>Independence</h2>
 * All expected (Rx, Ry) coordinates were computed by Python's {@code cryptography} library
 * (version 42.x, pyca/cryptography — a completely separate implementation), confirmed
 * correct by that library's own verification before being recorded here.  The Java code
 * under test is not involved in generating the expected values.
 *
 * <h2>Red-sensitivity</h2>
 * Each operation has a companion test that perturbs the scalar or a coordinate and asserts
 * the output does NOT match the known answer.  This confirms the tests would turn red if
 * the implementation produced a wrong-but-non-crashing result.
 *
 * <h2>Python cross-check commands (for audit)</h2>
 * <pre>
 * # pointMul P-256: k*G
 * python3 -c "from cryptography.hazmat.primitives.asymmetric import ec; \
 *   from cryptography.hazmat.backends import default_backend; \
 *   k=0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9; \
 *   p=ec.derive_private_key(k,ec.SECP256R1(),default_backend()); \
 *   n=p.public_key().public_numbers(); print(hex(n.x), hex(n.y))"
 * # Output: 0x523056e5...a318  0x3dc63da5...e571
 *
 * # pointAdd P-256: (k1*G) + (k2*G) == ((k1+k2) mod n)*G
 * # pointMulTwo P-256: K2*(k1*G) + B*G == (K2*k1+B mod n)*G
 * </pre>
 */
public class PKeyECPointArithmeticTest {

    // =========================================================================
    // P-256 known-answer data
    // =========================================================================

    // pointMul: k * G  (G = P-256 generator); result verified by Python cryptography 42.x
    private static final BigInteger K256 = new BigInteger(
            "de2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9", 16);
    private static final BigInteger MUL256_RX = new BigInteger(
            "523056e51624e416e8ff104d0a1f07355599f0c6b2f3aef90ada1c59e148a318", 16);
    private static final BigInteger MUL256_RY = new BigInteger(
            "3dc63da5c1f81b06f531d5ecde1b4b2a6c647b315ed1094f46b9fa1720a7e571", 16);

    // pointAdd: P + Q = R on P-256  where P = K256*G, Q = K2_256*G, R = ((K256+K2_256) mod n)*G
    private static final BigInteger K2_256 = new BigInteger(
            "c0d8b8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e7", 16);
    private static final BigInteger ADD256_QX = new BigInteger(
            "608109e76b9e5a9a3bcbd3f046174fe6ee2654927bb10f119add0fef2c047b56", 16);
    private static final BigInteger ADD256_QY = new BigInteger(
            "c4b35740646186ddf76354a359d0c3dc8c78cf0ecb2a7e3eaaef189f4600cb41", 16);
    private static final BigInteger ADD256_RX = new BigInteger(
            "f41be8f296860eee31cc1657ce19808ca34e0e8e70cb9a60b5bab426acf7de99", 16);
    private static final BigInteger ADD256_RY = new BigInteger(
            "783757efa47813453cd655640da34287cfce6f50478f8ec69197e7110d48e77a", 16);

    // pointMulTwo: K2_256*(K256*G) + B_256*G = (K2_256*K256 + B_256 mod n)*G, verified by Python
    private static final BigInteger B_256 = new BigInteger(
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", 16);
    private static final BigInteger MULTWO256_RX = new BigInteger(
            "baca0e40ab8c553931065f2767075b6531b3b0daab916e922d2f60196aa8115e", 16);
    private static final BigInteger MULTWO256_RY = new BigInteger(
            "9a36c5141e9680c556ae592e2e8c754931dc5661d3acafdc531b3eb31c7904d4", 16);

    // =========================================================================
    // P-384 known-answer data (pointMul k*G, verified by Python)
    // =========================================================================
    private static final BigInteger K384 = new BigInteger(
            "a4ebcae5a665983493ab3e626085a24c104311a761b5a8fdac052ed1f111a5c4" +
            "4f76f45659d2d111a61b5fdd97583480", 16);
    private static final BigInteger MUL384_RX = new BigInteger(
            "fda78b0ab4ac4b0ec6c66ac03ceb861637f0e2a2503f92be4abbf2b401e878ca" +
            "a799429b6cd63d7d7ab5dff1cc0a961b", 16);
    private static final BigInteger MUL384_RY = new BigInteger(
            "a07404ae3aed5e2df24fc0bf7c580e6761a882f571ff6642b7a4a7608b16f2cd" +
            "a6c659b8c4d56f5d0749c1838efbb1a6", 16);

    // =========================================================================
    // P-521 known-answer data (pointMul k*G, verified by Python)
    // =========================================================================
    private static final BigInteger K521 = new BigInteger(
            "1f746e23b7b5b448e15f7f9dd4a5d9ec3e42ca8f87c20c9a6b2fb8d5c79ad1e8" +
            "bf3e0f68a53cc79a3ebee93748476a7b0a2f18b48bba7c2ca83ed9e2c4cf1ab5b", 16);
    private static final BigInteger MUL521_RX = new BigInteger(
            "cf96e147b23a39a5663acb0a77197c37d1a7d25f43e9a9bb4cf4f5b2ef638fed" +
            "bc22e35eeec532aea2778a2c1b7ed32cf3c380047eab20fce96c66763561cb797a", 16);
    private static final BigInteger MUL521_RY = new BigInteger(
            "1951b19a36b011d72ab6c4084ede5bd5082ea33ec36a77e2c3a720c49d13f6c2b" +
            "94d6ea487def5f58dba75a82335c91a7124f66ea28a526acd35b17da646a37df72", 16);

    // =========================================================================
    // pointMul tests
    // =========================================================================

    @Test
    public void pointMul_P256_kTimesG() throws Exception {
        ECParameterSpec spec = spec("secp256r1");
        ECPoint result = callPointMul(spec, spec.getGenerator(), K256);

        assertEquals(MUL256_RX, result.getAffineX(),
                "P-256 pointMul: Rx must match Python-verified k*G");
        assertEquals(MUL256_RY, result.getAffineY(),
                "P-256 pointMul: Ry must match Python-verified k*G");
    }

    @Test
    public void pointMul_P256_wrongScalar_doesNotMatchExpected() throws Exception {
        ECParameterSpec spec = spec("secp256r1");
        ECPoint result = callPointMul(spec, spec.getGenerator(), K256.xor(BigInteger.ONE));

        assertFalse(MUL256_RX.equals(result.getAffineX()) && MUL256_RY.equals(result.getAffineY()),
                "P-256 pointMul red-sensitivity: wrong scalar must not equal expected point");
    }

    @Test
    public void pointMul_P384_kTimesG() throws Exception {
        ECParameterSpec spec = spec("secp384r1");
        ECPoint result = callPointMul(spec, spec.getGenerator(), K384);

        assertEquals(MUL384_RX, result.getAffineX(),
                "P-384 pointMul: Rx must match Python-verified k*G");
        assertEquals(MUL384_RY, result.getAffineY(),
                "P-384 pointMul: Ry must match Python-verified k*G");
    }

    @Test
    public void pointMul_P521_kTimesG() throws Exception {
        ECParameterSpec spec = spec("secp521r1");
        ECPoint result = callPointMul(spec, spec.getGenerator(), K521);

        assertEquals(MUL521_RX, result.getAffineX(),
                "P-521 pointMul: Rx must match Python-verified k*G");
        assertEquals(MUL521_RY, result.getAffineY(),
                "P-521 pointMul: Ry must match Python-verified k*G");
    }

    // =========================================================================
    // pointAdd tests
    // =========================================================================

    @Test
    public void pointAdd_P256_pPlusQ() throws Exception {
        ECParameterSpec spec = spec("secp256r1");
        ECPoint p = new ECPoint(MUL256_RX, MUL256_RY);  // K256*G
        ECPoint q = new ECPoint(ADD256_QX, ADD256_QY);   // K2_256*G

        ECPoint result = callPointAdd(spec, p, spec, q);

        assertEquals(ADD256_RX, result.getAffineX(),
                "P-256 pointAdd: Rx must match Python-verified (k1+k2)*G");
        assertEquals(ADD256_RY, result.getAffineY(),
                "P-256 pointAdd: Ry must match Python-verified (k1+k2)*G");
    }

    @Test
    public void pointAdd_P256_wrongPoint_doesNotMatchExpected() throws Exception {
        ECParameterSpec spec = spec("secp256r1");
        ECPoint p = new ECPoint(MUL256_RX, MUL256_RY);
        // Perturb Q's x coordinate — qBad is not on the curve
        ECPoint qBad = new ECPoint(ADD256_QX.xor(BigInteger.ONE), ADD256_QY);

        try {
            ECPoint result = callPointAdd(spec, p, spec, qBad);
            if (result != null) {
                assertFalse(ADD256_RX.equals(result.getAffineX()) && ADD256_RY.equals(result.getAffineY()),
                        "P-256 pointAdd red-sensitivity: perturbed Q must not yield expected R");
            }
        } catch (Exception ignored) {
            // Exception is acceptable: bc detected the invalid point
        }
    }

    // =========================================================================
    // pointMulTwo tests
    // =========================================================================

    @Test
    public void pointMulTwo_P256_aPlusbG() throws Exception {
        ECParameterSpec spec = spec("secp256r1");
        ECPoint p = new ECPoint(MUL256_RX, MUL256_RY);  // P = K256*G
        ECPoint g = spec.getGenerator();

        // BCInternal.pointMulTwo(selfSpec, P, K2_256, genSpec, G, B_256)
        // = sumOfTwoMultiplies(G, B_256, P, K2_256) = B_256*G + K2_256*P
        ECPoint result = callPointMulTwo(spec, p, K2_256, spec, g, B_256);

        assertEquals(MULTWO256_RX, result.getAffineX(),
                "P-256 pointMulTwo: Rx must match Python-verified (K2*P + B*G)");
        assertEquals(MULTWO256_RY, result.getAffineY(),
                "P-256 pointMulTwo: Ry must match Python-verified (K2*P + B*G)");
    }

    @Test
    public void pointMulTwo_P256_wrongScalar_doesNotMatchExpected() throws Exception {
        ECParameterSpec spec = spec("secp256r1");
        ECPoint p = new ECPoint(MUL256_RX, MUL256_RY);
        ECPoint g = spec.getGenerator();

        ECPoint result = callPointMulTwo(spec, p, K2_256.xor(BigInteger.ONE), spec, g, B_256);

        assertFalse(MULTWO256_RX.equals(result.getAffineX()) && MULTWO256_RY.equals(result.getAffineY()),
                "P-256 pointMulTwo red-sensitivity: wrong scalar must not equal expected point");
    }

    // =========================================================================
    // decodePoint tests
    // =========================================================================

    @Test
    public void decodePoint_P256_uncompressedRoundTrip() throws Exception {
        ECParameterSpec spec = spec("secp256r1");

        // Build uncompressed encoding of the K256*G point: 0x04 || x (32 bytes) || y (32 bytes)
        byte[] encoded = new byte[65];
        encoded[0] = 0x04;
        System.arraycopy(toBytes32(MUL256_RX), 0, encoded, 1, 32);
        System.arraycopy(toBytes32(MUL256_RY), 0, encoded, 33, 32);

        ECPoint result = callDecodePoint(spec, encoded);

        assertEquals(MUL256_RX, result.getAffineX(), "decodePoint P-256: decoded x must match");
        assertEquals(MUL256_RY, result.getAffineY(), "decodePoint P-256: decoded y must match");
    }

    @Test
    public void decodePoint_P256_compressedPoint() throws Exception {
        ECParameterSpec spec = spec("secp256r1");

        // Even/odd prefix: 0x02 if y is even, 0x03 if y is odd
        byte prefix = MUL256_RY.testBit(0) ? (byte) 0x03 : (byte) 0x02;
        byte[] encoded = new byte[33];
        encoded[0] = prefix;
        System.arraycopy(toBytes32(MUL256_RX), 0, encoded, 1, 32);

        ECPoint result = callDecodePoint(spec, encoded);

        assertEquals(MUL256_RX, result.getAffineX(), "decodePoint P-256 compressed: x must match");
        assertEquals(MUL256_RY, result.getAffineY(), "decodePoint P-256 compressed: y must match");
    }

    @Test
    public void decodePoint_P256_wrongBytes_throws() throws Exception {
        ECParameterSpec spec = spec("secp256r1");

        // Corrupt the y coordinate — point is not on the curve
        byte[] encoded = new byte[65];
        encoded[0] = 0x04;
        System.arraycopy(toBytes32(MUL256_RX), 0, encoded, 1, 32);
        System.arraycopy(toBytes32(MUL256_RY.xor(BigInteger.ONE)), 0, encoded, 33, 32);

        // bc-fips ECCurve.decodePoint validates the point lies on the curve
        assertThrows(Exception.class, () -> callDecodePoint(spec, encoded),
                "decodePoint: off-curve bytes must throw");
    }

    // =========================================================================
    // helpers
    // =========================================================================

    private static ECParameterSpec spec(String stdName) throws Exception {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec(stdName));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    private static ECPoint callPointMul(ECParameterSpec spec, ECPoint self, BigInteger scalar)
            throws Exception {
        Method m = bcInternal().getDeclaredMethod(
                "pointMul", ECParameterSpec.class, ECPoint.class, BigInteger.class);
        m.setAccessible(true);
        return (ECPoint) m.invoke(null, spec, self, scalar);
    }

    private static ECPoint callPointAdd(ECParameterSpec selfSpec, ECPoint self,
                                         ECParameterSpec otherSpec, ECPoint other)
            throws Exception {
        Method m = bcInternal().getDeclaredMethod(
                "pointAdd", ECParameterSpec.class, ECPoint.class,
                            ECParameterSpec.class, ECPoint.class);
        m.setAccessible(true);
        return (ECPoint) m.invoke(null, selfSpec, self, otherSpec, other);
    }

    private static ECPoint callPointMulTwo(ECParameterSpec selfSpec, ECPoint self, BigInteger bn,
                                            ECParameterSpec genSpec, ECPoint generator, BigInteger bn_g)
            throws Exception {
        Method m = bcInternal().getDeclaredMethod(
                "pointMulTwo",
                ECParameterSpec.class, ECPoint.class, BigInteger.class,
                ECParameterSpec.class, ECPoint.class, BigInteger.class);
        m.setAccessible(true);
        return (ECPoint) m.invoke(null, selfSpec, self, bn, genSpec, generator, bn_g);
    }

    private static ECPoint callDecodePoint(ECParameterSpec spec, byte[] encoded) throws Exception {
        Method m = bcInternal().getDeclaredMethod("decodePoint", ECParameterSpec.class, byte[].class);
        m.setAccessible(true);
        return (ECPoint) m.invoke(null, spec, encoded);
    }

    private static Class<?> bcInternal() throws ClassNotFoundException {
        return Class.forName("org.jruby.ext.openssl.PKeyEC$BCInternal");
    }

    /** Big-endian 32-byte encoding of a BigInteger (zero-padded, no sign byte). */
    private static byte[] toBytes32(BigInteger v) {
        byte[] raw = v.toByteArray();
        if (raw.length == 32) return raw;
        byte[] out = new byte[32];
        if (raw.length < 32) {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        } else {
            // raw has a leading zero sign byte — strip it
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        }
        return out;
    }
}
