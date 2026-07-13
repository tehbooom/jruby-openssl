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
    // P-384 known-answer data for pointAdd and pointMulTwo (verified by Python)
    //
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    // Note: K2_384 > n, so the effective scalar is K2_384 % n.
    // Q = ec.derive_private_key(K2_384 % n, SECP384R1(), backend).public_key().public_numbers()
    // ADD result: ec.derive_private_key((K384 + K2_384) % n, SECP384R1(), backend).public_key().public_numbers()
    // MULTWO result: ec.derive_private_key((K2_384 * K384 + B_384) % n, SECP384R1(), backend).public_key().public_numbers()
    // =========================================================================
    private static final BigInteger K2_384 = new BigInteger(
            "b3d4e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3" +
            "e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3", 16);
    // ADD384_QX/QY = (K2_384 mod n)*G, Python cryptography 42.x
    private static final BigInteger ADD384_QX = new BigInteger(
            "c377da41788dda12d649d6921e8379e9c02b1567b6561e269e65a987a8a4bdaa" +
            "486701a9ddfa8a03bdad82b96b4072ed", 16);
    private static final BigInteger ADD384_QY = new BigInteger(
            "ddd51a59d1bcc8dcd1e7c46ade71aacabd11b110649625e8da47f66016b4b12b" +
            "7e697828d0c23df573de398dbffe5277", 16);
    // ADD384_RX/RY = (K384 + K2_384 mod n)*G, Python cryptography 42.x
    private static final BigInteger ADD384_RX = new BigInteger(
            "a74bb33f798ee39a28b3f5dffbf9cea2f6fee2cbd8176d707822aaeba72c88ac" +
            "6079f58024982a0ddb512f17c5986fe6", 16);
    private static final BigInteger ADD384_RY = new BigInteger(
            "c21a75b60b28aba74acfc53b5b485a9600d8333e29e7081703647213d2592154" +
            "a1383e35140533a5a16f559cbf1ec4ab", 16);

    private static final BigInteger B_384 = new BigInteger(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" +
            "fedcba9876543210fedcba9876543210", 16);
    // MULTWO384_RX/RY = (K2_384*K384 + B_384 mod n)*G, Python cryptography 42.x
    private static final BigInteger MULTWO384_RX = new BigInteger(
            "fe32b134fad008385c3b0bf35cfc7f6a251bb8c2ca3f97ef03241ff20210a963" +
            "ea954827aeee29a134ed15aeaaaa92ed", 16);
    private static final BigInteger MULTWO384_RY = new BigInteger(
            "4ad711608fd173cb274e127b70c1bda8e317f068aeac4b1a1cf79fcda0f9aa1c" +
            "42d0896007efa1ecf682f56270a3fa3b", 16);

    // =========================================================================
    // P-521 known-answer data for pointAdd and pointMulTwo (verified by Python)
    //
    // Python cross-check commands:
    //   K2_521 = 0x00a1b2...f0; B_521 = 0x10fedc...10
    //   # pointAdd: P=K521*G, Q=K2_521*G, R=(K521+K2_521 mod n)*G
    //   # pointMulTwo: (K2_521*K521 + B_521 mod n)*G
    // =========================================================================
    private static final BigInteger K2_521 = new BigInteger(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0" +
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", 16);
    private static final BigInteger ADD521_QX = new BigInteger(
            "78de28289192d4869ccb9d981bf9944a694baf835cab832858f22031a2342205" +
            "287c1d8978efd6e477f3f912ec1bbf2d5e6ec2e800872ea83e6aab45fb2ca743f2", 16);
    private static final BigInteger ADD521_QY = new BigInteger(
            "64e06b5aad28dec3425e297b50176c8e5795b55265904809de09189923cf28f1" +
            "d8902aadffcee3b1150e5dd9f65d612773e1b7e07900e29f9e61ad86776ba1be0e", 16);
    private static final BigInteger ADD521_RX = new BigInteger(
            "1a857730519cb0367e43c95277169daa58984c281ba34c2d605f12ee178b13202" +
            "3cff4cf87db8ab5212c0661de8b42d16c46ab2cb0f3dbc6a69fb629bb51ebb3ff6", 16);
    private static final BigInteger ADD521_RY = new BigInteger(
            "116275f77014ae24f1d13f7fdd0905af098e7d3421a4c59ff5f2ab97a19fcbce" +
            "c0d1177452158f5387e2ee090ad410bc96f319347530448e543acb5814acae2b896", 16);

    private static final BigInteger B_521 = new BigInteger(
            "10fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" +
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 16);
    private static final BigInteger MULTWO521_RX = new BigInteger(
            "12a442225e25af6fdf7895fce64feacf3c3fff590c95ed0feec645f23c12b2074" +
            "b1dfbc9eb422ab049fa29a11d98b59414ffea5621212b47fc4d8440c6c98174c71", 16);
    private static final BigInteger MULTWO521_RY = new BigInteger(
            "82261975596b99466e4281dfbcc62381f75370aa4a58ac038dea2b3abd99e311e" +
            "a543868a84470cb9f3f0dc24438887f7ed1257c505e5b5fe18958f2bf5a1a8102", 16);

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

    @Test
    public void pointAdd_P384_pPlusQ() throws Exception {
        ECParameterSpec spec = spec("secp384r1");
        ECPoint p = new ECPoint(MUL384_RX, MUL384_RY);     // K384*G
        ECPoint q = new ECPoint(ADD384_QX, ADD384_QY);      // K2_384*G

        ECPoint result = callPointAdd(spec, p, spec, q);

        assertEquals(ADD384_RX, result.getAffineX(),
                "P-384 pointAdd: Rx must match Python-verified (k1+k2)*G");
        assertEquals(ADD384_RY, result.getAffineY(),
                "P-384 pointAdd: Ry must match Python-verified (k1+k2)*G");
    }

    @Test
    public void pointAdd_P521_pPlusQ() throws Exception {
        ECParameterSpec spec = spec("secp521r1");
        ECPoint p = new ECPoint(MUL521_RX, MUL521_RY);     // K521*G
        ECPoint q = new ECPoint(ADD521_QX, ADD521_QY);      // K2_521*G

        ECPoint result = callPointAdd(spec, p, spec, q);

        assertEquals(ADD521_RX, result.getAffineX(),
                "P-521 pointAdd: Rx must match Python-verified (k1+k2)*G");
        assertEquals(ADD521_RY, result.getAffineY(),
                "P-521 pointAdd: Ry must match Python-verified (k1+k2)*G");
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

    @Test
    public void pointMulTwo_P384_aPlusbG() throws Exception {
        ECParameterSpec spec = spec("secp384r1");
        ECPoint p = new ECPoint(MUL384_RX, MUL384_RY);  // P = K384*G
        ECPoint g = spec.getGenerator();

        // BCInternal.pointMulTwo(selfSpec, P, K2_384, genSpec, G, B_384)
        // = sumOfTwoMultiplies(G, B_384, P, K2_384) = B_384*G + K2_384*P
        ECPoint result = callPointMulTwo(spec, p, K2_384, spec, g, B_384);

        assertEquals(MULTWO384_RX, result.getAffineX(),
                "P-384 pointMulTwo: Rx must match Python-verified (K2*P + B*G)");
        assertEquals(MULTWO384_RY, result.getAffineY(),
                "P-384 pointMulTwo: Ry must match Python-verified (K2*P + B*G)");
    }

    @Test
    public void pointMulTwo_P521_aPlusbG() throws Exception {
        ECParameterSpec spec = spec("secp521r1");
        ECPoint p = new ECPoint(MUL521_RX, MUL521_RY);  // P = K521*G
        ECPoint g = spec.getGenerator();

        // BCInternal.pointMulTwo(selfSpec, P, K2_521, genSpec, G, B_521)
        // = sumOfTwoMultiplies(G, B_521, P, K2_521) = B_521*G + K2_521*P
        ECPoint result = callPointMulTwo(spec, p, K2_521, spec, g, B_521);

        assertEquals(MULTWO521_RX, result.getAffineX(),
                "P-521 pointMulTwo: Rx must match Python-verified (K2*P + B*G)");
        assertEquals(MULTWO521_RY, result.getAffineY(),
                "P-521 pointMulTwo: Ry must match Python-verified (K2*P + B*G)");
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
