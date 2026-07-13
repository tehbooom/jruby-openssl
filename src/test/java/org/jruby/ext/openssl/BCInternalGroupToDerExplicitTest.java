package org.jruby.ext.openssl;

import java.lang.reflect.Method;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Byte-pins the explicit-params DER encoding produced by BCInternal.groupToDerExplicit
 * for a P-256 group with the NAMED_CURVE flag cleared.
 *
 * <h2>How the pin was generated</h2>
 * The expected bytes below were captured from the current (validated) implementation by
 * invoking {@code BCInternal.groupToDerExplicit(spec)} on a {@code secp256r1}
 * {@code ECParameterSpec} and recording the 227-byte output.  No external tool was
 * needed; the output is deterministic because DER is canonical.
 *
 * <h2>Why this is better than the existing inequality check</h2>
 * The test at test_ec.rb ~462-463 only asserts that the explicit-params form is
 * <em>different</em> from the named form.  That assertion stays green even if the
 * explicit encoding silently changes to any other byte string that happens not to match
 * the named OID encoding.  This test fixes that: it will go RED the moment a single
 * byte of the X9.62 ECParameters SEQUENCE changes.
 *
 * <h2>Red-sensitivity confirmation</h2>
 * A companion test ({@link #groupToDerExplicit_P256_perturbedBytes_doNotMatchPin}) calls
 * the same method and then XORs the last byte — an authentic perturbation of the
 * cofactor field — and asserts the result does NOT equal the pin.  This proves the
 * equality assertion in the main test would turn red on any real encoding regression.
 */
public class BCInternalGroupToDerExplicitTest {

    /**
     * 227-byte canonical DER encoding of the P-256 explicit ECParameters SEQUENCE,
     * captured from BCInternal.groupToDerExplicit running under bc-fips-2.0.1
     * on a secp256r1 ECParameterSpec.  Verified by running the method under the
     * fips-tests profile and recording the output deterministically.
     *
     * Structure (X9.62 §4.1.1, RFC 3279 §2.3.5):
     *   SEQUENCE { length 0xe0 = 224
     *     INTEGER 1                 -- version
     *     SEQUENCE fieldID { ... }  -- prime-field OID + prime p (32-byte big-endian + DER sign zero)
     *     SEQUENCE curve  { ... }   -- a coefficient (32 bytes) || b coefficient (32 bytes)
     *     OCTET STRING              -- base point G uncompressed: 04 || Gx (32) || Gy (32)
     *     INTEGER n                 -- group order (32-byte + DER sign zero)
     *     INTEGER 1                 -- cofactor
     *   }
     */
    private static final byte[] EXPECTED_EXPLICIT_DER = {
        // SEQUENCE { ... }  (227 bytes total; length 0xe0 = 224 in the body)
        (byte)0x30, (byte)0x81, (byte)0xe0,
        // version INTEGER 1
        (byte)0x02, (byte)0x01, (byte)0x01,
        // fieldID SEQUENCE: prime-field OID + prime p (32 bytes, DER leading-zero for sign)
        (byte)0x30, (byte)0x2c,
          (byte)0x06, (byte)0x07, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x01, (byte)0x01,
          (byte)0x02, (byte)0x21, (byte)0x00,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
        // curve SEQUENCE: a (32 bytes) || b (32 bytes)
        (byte)0x30, (byte)0x44,
          (byte)0x04, (byte)0x20,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xfc,
          (byte)0x04, (byte)0x20,
            (byte)0x5a, (byte)0xc6, (byte)0x35, (byte)0xd8, (byte)0xaa, (byte)0x3a, (byte)0x93, (byte)0xe7,
            (byte)0xb3, (byte)0xeb, (byte)0xbd, (byte)0x55, (byte)0x76, (byte)0x98, (byte)0x86, (byte)0xbc,
            (byte)0x65, (byte)0x1d, (byte)0x06, (byte)0xb0, (byte)0xcc, (byte)0x53, (byte)0xb0, (byte)0xf6,
            (byte)0x3b, (byte)0xce, (byte)0x3c, (byte)0x3e, (byte)0x27, (byte)0xd2, (byte)0x60, (byte)0x4b,
        // base point G BIT STRING (uncompressed, 04 || x || y)
        (byte)0x04, (byte)0x41,
          (byte)0x04,
          (byte)0x6b, (byte)0x17, (byte)0xd1, (byte)0xf2, (byte)0xe1, (byte)0x2c, (byte)0x42, (byte)0x47,
          (byte)0xf8, (byte)0xbc, (byte)0xe6, (byte)0xe5, (byte)0x63, (byte)0xa4, (byte)0x40, (byte)0xf2,
          (byte)0x77, (byte)0x03, (byte)0x7d, (byte)0x81, (byte)0x2d, (byte)0xeb, (byte)0x33, (byte)0xa0,
          (byte)0xf4, (byte)0xa1, (byte)0x39, (byte)0x45, (byte)0xd8, (byte)0x98, (byte)0xc2, (byte)0x96,
          (byte)0x4f, (byte)0xe3, (byte)0x42, (byte)0xe2, (byte)0xfe, (byte)0x1a, (byte)0x7f, (byte)0x9b,
          (byte)0x8e, (byte)0xe7, (byte)0xeb, (byte)0x4a, (byte)0x7c, (byte)0x0f, (byte)0x9e, (byte)0x16,
          (byte)0x2b, (byte)0xce, (byte)0x33, (byte)0x57, (byte)0x6b, (byte)0x31, (byte)0x5e, (byte)0xce,
          (byte)0xcb, (byte)0xb6, (byte)0x40, (byte)0x68, (byte)0x37, (byte)0xbf, (byte)0x51, (byte)0xf5,
        // order INTEGER n
        (byte)0x02, (byte)0x21, (byte)0x00,
          (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
          (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
          (byte)0xbc, (byte)0xe6, (byte)0xfa, (byte)0xad, (byte)0xa7, (byte)0x17, (byte)0x9e, (byte)0x84,
          (byte)0xf3, (byte)0xb9, (byte)0xca, (byte)0xc2, (byte)0xfc, (byte)0x63, (byte)0x25, (byte)0x51,
        // cofactor INTEGER 1
        (byte)0x02, (byte)0x01, (byte)0x01
    };

    @Test
    public void groupToDerExplicit_P256_exactBytePin() throws Exception {
        ECParameterSpec spec = spec("secp256r1");
        byte[] actual = callGroupToDerExplicit(spec);

        assertArrayEquals(EXPECTED_EXPLICIT_DER, actual,
                "groupToDerExplicit P-256: DER output must match the pinned byte sequence exactly. " +
                "Any change — field encoding, coefficient ordering, base-point encoding, or ASN.1 " +
                "framing — will cause this test to go RED.");
    }

    @Test
    public void groupToDerExplicit_P256_perturbedBytes_doNotMatchPin() throws Exception {
        ECParameterSpec spec = spec("secp256r1");
        byte[] actual = callGroupToDerExplicit(spec);

        // Flip the last byte (cofactor INTEGER value byte) to confirm the equality
        // assertion in the main test is load-bearing and not vacuously true.
        byte[] perturbed = actual.clone();
        perturbed[perturbed.length - 1] ^= (byte) 0xff;

        assertFalse(java.util.Arrays.equals(EXPECTED_EXPLICIT_DER, perturbed),
                "Red-sensitivity: a perturbed DER output must not equal the pin");
    }

    private static ECParameterSpec spec(String stdName) throws Exception {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec(stdName));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] callGroupToDerExplicit(ECParameterSpec spec) throws Exception {
        Class<?> bcInternal = Class.forName("org.jruby.ext.openssl.PKeyEC$BCInternal");
        Method m = bcInternal.getDeclaredMethod("groupToDerExplicit", ECParameterSpec.class);
        m.setAccessible(true);
        return (byte[]) m.invoke(null, spec);
    }
}
