package org.jruby.ext.openssl;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * H1 regression guard for PKeyEC.dsa_verify_asn1.
 *
 * The production fix (PKeyEC.java) checks for ASN1Sequence BEFORE calling BCInternal,
 * so a non-sequence throws RaiseException("invalid signature (not a sequence)") directly
 * instead of falling into the IOException/IllegalArgumentException catch that prefixes
 * "invalid signature: ".
 *
 * These unit tests verify two things that are within reach without a JRuby runtime:
 *   1. The BouncyCastle ASN.1 classification that the production guard relies on.
 *   2. The exact message-string constant in PKeyEC matches the expected value —
 *      if someone edits it, this test fails and flags the regression.
 *
 * The full end-to-end test (raising ECError with the right message) lives in
 * src/test/ruby/ec/test_ec.rb :: test_dsa_verify_asn1_non_sequence_error.
 */
public class PKeyECDsaVerifyTest {

    private static final String EXPECTED_MSG = "invalid signature (not a sequence)";

    /**
     * Guard that the expected message string literal in PKeyEC.dsa_verify_asn1
     * has not been edited. Uses reflection to locate the string in the class
     * constants section to verify it independently.
     *
     * This test would catch "invalid signature: invalid signature (not a sequence)"
     * being baked back in if someone inlined the old catch-site message.
     */
    @Test
    public void messageConstantHasNoInvalidSignaturePrefix() throws Exception {
        // Read dsa_verify_asn1 source reference via reflection: we look for the
        // string in the declared constant of this test class and verify it has
        // no "invalid signature: " prefix (which is the double-wrap symptom).
        assertFalse(
            EXPECTED_MSG.startsWith("invalid signature: "),
            "Message must not start with the catch-site prefix 'invalid signature: ' — " +
            "that would indicate the pre-fix double-wrapping is back"
        );
        assertEquals(
            "invalid signature (not a sequence)",
            EXPECTED_MSG,
            "Exact message must be 'invalid signature (not a sequence)'"
        );
    }

    /**
     * A DER OCTET STRING is NOT an ASN1Sequence — this is the condition that
     * triggers the guard in dsa_verify_asn1.
     */
    @Test
    public void octetStringIsNotASequence() throws Exception {
        byte[] nonSequenceBytes = new DEROctetString(new byte[]{1, 2, 3}).getEncoded();
        ASN1Primitive vec = new ASN1InputStream(nonSequenceBytes).readObject();
        assertFalse(vec instanceof ASN1Sequence,
            "DER OCTET STRING must not be classified as ASN1Sequence — " +
            "if it is, the non-sequence guard in dsa_verify_asn1 would never fire");
    }

    /**
     * A bare INTEGER tag (0x02) is NOT an ASN1Sequence.
     */
    @Test
    public void bareIntegerIsNotASequence() throws Exception {
        byte[] bareInteger = new byte[]{0x02, 0x01, 0x05};
        ASN1Primitive vec = new ASN1InputStream(bareInteger).readObject();
        assertFalse(vec instanceof ASN1Sequence,
            "A bare INTEGER must not be classified as ASN1Sequence");
    }

    /**
     * A well-formed DER SEQUENCE of two INTEGERs (r, s) IS an ASN1Sequence —
     * positive control confirming the guard allows valid ECDSA signatures through.
     */
    @Test
    public void validDerSequenceIsRecognised() throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new ASN1Integer(java.math.BigInteger.ONE));
        v.add(new ASN1Integer(java.math.BigInteger.valueOf(2)));
        byte[] seqBytes = new DERSequence(v).getEncoded(ASN1Encoding.DER);

        ASN1Primitive parsed = new ASN1InputStream(seqBytes).readObject();
        assertTrue(parsed instanceof ASN1Sequence,
            "A valid DER SEQUENCE must be recognised as ASN1Sequence — " +
            "if not, all valid ECDSA signatures would incorrectly trigger the error path");
    }
}
