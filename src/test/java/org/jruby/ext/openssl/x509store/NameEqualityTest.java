package org.jruby.ext.openssl.x509store;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * M1 regression: DN comparison must succeed when subject and issuer use the same
 * logical name but different ASN.1 string encodings (PrintableString vs UTF8String).
 *
 * Background: the original code had a fast-path through X509CertificateObject for
 * non-FIPS BC (encoding-tolerant). That class is absent in bc-fips so the path was
 * already dead under FIPS.  The current code always uses X500Principal.equals, which
 * RFC-4514-normalises and is also encoding-tolerant.  This test proves it.
 */
public class NameEqualityTest {

    private static final ASN1ObjectIdentifier CN_OID = new ASN1ObjectIdentifier("2.5.4.3");

    // Build a DER X500Name where CN is encoded as PrintableString
    private static X500Name nameWithPrintableString(String cn) {
        ASN1EncodableVector atv = new ASN1EncodableVector();
        atv.add(CN_OID);
        atv.add(new DERPrintableString(cn));
        ASN1EncodableVector rdn = new ASN1EncodableVector();
        rdn.add(new DERSequence(atv));
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(new DERSet(rdn));
        return X500Name.getInstance(new DERSequence(seq));
    }

    // Build a DER X500Name where CN is encoded as UTF8String
    private static X500Name nameWithUTF8String(String cn) {
        ASN1EncodableVector atv = new ASN1EncodableVector();
        atv.add(CN_OID);
        atv.add(new DERUTF8String(cn));
        ASN1EncodableVector rdn = new ASN1EncodableVector();
        rdn.add(new DERSequence(atv));
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(new DERSet(rdn));
        return X500Name.getInstance(new DERSequence(seq));
    }

    private static X509Certificate buildCert(X500Name subject, KeyPair kp) throws Exception {
        X500Name issuer = subject;
        BigInteger serial = BigInteger.ONE;
        Date notBefore = new Date(System.currentTimeMillis() - 86400_000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400_000L);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, spki);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    public void nameEqualToCertSubjectPrintableMatchesUTF8() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        X500Name printableName = nameWithPrintableString("Test CA");
        X500Name utf8Name      = nameWithUTF8String("Test CA");

        // The two DER encodings are byte-for-byte different
        assertFalse(java.util.Arrays.equals(printableName.getEncoded(), utf8Name.getEncoded()),
                "DER encodings must differ to be a meaningful test");

        // Build a cert whose subject is UTF8String-encoded
        X509Certificate utf8Cert = buildCert(utf8Name, kp);
        X509AuxCertificate auxCert = new X509AuxCertificate(utf8Cert);

        // Name built from PrintableString-encoded principal
        Name printableName2 = new Name(new X500Principal(printableName.getEncoded()));

        // equalToCertificateSubject must return true despite encoding difference
        assertTrue(printableName2.equalToCertificateSubject(auxCert),
                "equalToCertificateSubject must match across PrintableString/UTF8String encoding");
    }

    @Test
    public void equalSubjectsPrintableVsUTF8() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        X500Name printableName = nameWithPrintableString("Issuer CN");
        X500Name utf8Name      = nameWithUTF8String("Issuer CN");

        X509Certificate printableCert = buildCert(printableName, kp);
        X509Certificate utf8Cert      = buildCert(utf8Name, kp);

        X509AuxCertificate aux1 = new X509AuxCertificate(printableCert);
        X509AuxCertificate aux2 = new X509AuxCertificate(utf8Cert);

        assertTrue(X509AuxCertificate.equalSubjects(aux1, aux2),
                "equalSubjects must match across PrintableString/UTF8String encoding");
    }
}
