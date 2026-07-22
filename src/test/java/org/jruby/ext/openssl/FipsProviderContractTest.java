package org.jruby.ext.openssl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.Base64;
import java.util.IdentityHashMap;
import java.util.Set;

import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.operator.ContentSigner;
import org.jruby.Ruby;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Runs only under the fips-tests profile. The profile excludes non-FIPS BC,
 * while this fixture performs the deployment-owned provider registration.
 */
public class FipsProviderContractTest {

    private static Provider configuredProvider;
    private static Provider configuredSslProvider;

    @BeforeAll
    static void registerConfiguredProvider() throws Exception {
        FipsTestEnvironment.registerConfiguredProviders();
        configuredProvider = FipsTestEnvironment.configuredProvider();
        configuredSslProvider = FipsTestEnvironment.configuredSslProvider();
    }

    @AfterAll
    static void removeConfiguredProvider() {
        FipsTestEnvironment.removeConfiguredProviders();
        configuredProvider = null;
        configuredSslProvider = null;
    }

    private static void assertConfigured(final String operation, final Provider actual) {
        assertEquals(configuredProvider.getName(), actual.getName(), operation);
        System.out.println(operation + " provider=" + actual.getName());
    }

    @Test
    void opensslFipsConstantIsTrueInStrictMode() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            assertTrue(runtime.evalScriptlet("OpenSSL::OPENSSL_FIPS").isTrue());
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void setDefaultPathsHonorsConfiguredBcfksTrustStore() throws Exception {
        final Path trustStore = Files.createTempFile("jruby-openssl-fips-truststore", ".bcfks");
        final char[] password = "changeit".toCharArray();
        final String[] properties = {
                "javax.net.ssl.trustStore",
                "javax.net.ssl.trustStoreType",
                "javax.net.ssl.trustStoreProvider",
                "javax.net.ssl.trustStorePassword"
        };
        final String[] previousValues = new String[properties.length];
        Ruby runtime = null;

        try {
            final X509Certificate certificate;
            try (FileInputStream input = new FileInputStream("src/test/ruby/x509/ec-ca.crt")) {
                certificate = (X509Certificate)
                        SecurityHelper.getCertificateFactory("X.509").generateCertificate(input);
            }

            final KeyStore bcfks = KeyStore.getInstance("BCFKS", configuredProvider);
            bcfks.load(null, password);
            bcfks.setCertificateEntry("synthetic-ca", certificate);
            try (FileOutputStream output = new FileOutputStream(trustStore.toFile())) {
                bcfks.store(output, password);
            }

            for (int i = 0; i < properties.length; i++) {
                previousValues[i] = System.getProperty(properties[i]);
            }
            System.setProperty("javax.net.ssl.trustStore", trustStore.toString());
            System.setProperty("javax.net.ssl.trustStoreType", "BCFKS");
            System.setProperty("javax.net.ssl.trustStoreProvider", configuredProvider.getName());
            System.setProperty("javax.net.ssl.trustStorePassword", new String(password));

            runtime = Ruby.newInstance();
            OpenSSL.createOpenSSL(runtime);
            runtime.evalScriptlet(
                    "ENV.delete('SSL_CERT_FILE')\n" +
                    "certificate = OpenSSL::X509::Certificate.new(" +
                    "File.binread('src/test/ruby/x509/ec-ca.crt'))\n" +
                    "store = OpenSSL::X509::Store.new\n" +
                    "store.set_default_paths\n" +
                    "raise 'configured BCFKS trust anchor was not loaded' unless store.verify(certificate)\n");
        }
        finally {
            if (runtime != null) runtime.tearDown(false);
            for (int i = 0; i < properties.length; i++) {
                if (previousValues[i] == null) {
                    System.clearProperty(properties[i]);
                }
                else {
                    System.setProperty(properties[i], previousValues[i]);
                }
            }
            Files.deleteIfExists(trustStore);
        }
    }

    private static Signature contentSignerSignature(final ContentSigner signer) throws Exception {
        final Signature signature = findSignature(signer,
                Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>()), 0);
        if (signature != null) return signature;
        throw new AssertionError("ContentSigner did not expose its internal Signature");
    }

    private static Signature findSignature(final Object object,
            final Set<Object> visited, final int depth) throws Exception {
        if (object == null || depth > 4 || !visited.add(object)) return null;
        if (object instanceof Signature) return (Signature) object;

        Class<?> type = object.getClass();
        while (type != null) {
            for (Field field : type.getDeclaredFields()) {
                field.setAccessible(true);
                final Object value = field.get(object);
                if (value instanceof Signature) return (Signature) value;
                if (value != null && value.getClass().getName().startsWith("org.bouncycastle.")) {
                    final Signature nested = findSignature(value, visited, depth + 1);
                    if (nested != null) return nested;
                }
            }
            type = type.getSuperclass();
        }
        return null;
    }

    private static final class TrackingSecureRandom extends SecureRandom {
        private int nextBytesCalls;

        @Override
        public void nextBytes(final byte[] bytes) {
            nextBytesCalls++;
            super.nextBytes(bytes);
        }
    }

    public static final class TrackingDefaultSecureRandomSpi extends SecureRandomSpi {
        private static int nextBytesCalls;

        @Override
        protected void engineSetSeed(final byte[] seed) {
        }

        @Override
        protected void engineNextBytes(final byte[] bytes) {
            nextBytesCalls++;
            for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (i + 1);
        }

        @Override
        protected byte[] engineGenerateSeed(final int numBytes) {
            final byte[] seed = new byte[numBytes];
            engineNextBytes(seed);
            return seed;
        }
    }

    private static final class TrackingDefaultRandomProvider extends Provider {
        private TrackingDefaultRandomProvider() {
            super("JOSSL_TRACKING_DEFAULT_RANDOM", 1.0,
                    "detects accidental use of new SecureRandom()");
            put("SecureRandom.JOSSL-TRACKING", TrackingDefaultSecureRandomSpi.class.getName());
        }
    }

    @Test
    void sslContextsUseConfiguredRegisteredJsseProvider() throws Exception {
        for (String protocol : new String[] { "SSL", "TLS", "TLSv1.2", "TLSv1.3" }) {
            final SSLContext context = SecurityHelper.getSSLContext(protocol);
            assertEquals(configuredSslProvider.getName(), context.getProvider().getName());
            System.out.println(protocol + " SSLContext provider=" + context.getProvider().getName());
        }
        assertThrows(java.security.NoSuchAlgorithmException.class,
                () -> SecurityHelper.getSSLContext("SSLv2"));

        Security.removeProvider(configuredSslProvider.getName());
        try {
            assertThrows(IllegalStateException.class,
                    () -> SecurityHelper.getSSLContext("TLS"));
        }
        finally {
            Security.addProvider(configuredSslProvider);
        }
    }

    @Test
    void ecKeepOperationConsumesConfiguredSecureRandom() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);

            final TrackingSecureRandom jdkContextRandom = new TrackingSecureRandom();
            runtime.getCurrentContext().secureRandom = jdkContextRandom;
            final SecureRandom consumed = OpenSSL.getSecureRandom(runtime.getCurrentContext());
            assertConfigured("EC generation SecureRandom", consumed.getProvider());

            runtime.evalScriptlet("OpenSSL::PKey::EC.generate('prime256v1')");
            assertEquals(0, jdkContextRandom.nextBytesCalls,
                    "EC generation must not consume the JRuby/JDK context random");
            System.out.println("EC generation context random provider=" +
                    consumed.getProvider().getName() + ", JDK context calls=" +
                    jdkContextRandom.nextBytesCalls);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void encryptedPrivatePemConsumesConfiguredSecureRandom() {
        final Ruby runtime = Ruby.newInstance();
        final Provider trackingProvider = new TrackingDefaultRandomProvider();
        try {
            OpenSSL.createOpenSSL(runtime);
            runtime.evalScriptlet("$fips_contract_rsa = OpenSSL::PKey::RSA.generate(2048)");

            TrackingDefaultSecureRandomSpi.nextBytesCalls = 0;
            Security.insertProviderAt(trackingProvider, 1);
            runtime.evalScriptlet(
                    "$fips_contract_rsa.private_to_pem(" +
                    "OpenSSL::Cipher.new('AES-256-CBC'), 'password')");

            assertEquals(0, TrackingDefaultSecureRandomSpi.nextBytesCalls,
                    "PKCS#8 encryption must not consume the default-provider SecureRandom");
            assertConfigured("PKCS#8 encryption SecureRandom",
                    SecurityHelper.getSecureRandom().getProvider());
        }
        finally {
            Security.removeProvider(trackingProvider.getName());
            runtime.tearDown(false);
        }
    }

    @Test
    void certificateCrlAndOcspContentSignersUseConfiguredProvider() throws Exception {
        final KeyPairGenerator generator = SecurityHelper.getKeyPairGenerator("RSA");
        generator.initialize(2048, SecurityHelper.getSecureRandom());
        final KeyPair pair = generator.generateKeyPair();

        final ContentSigner certSigner =
                X509Cert.newJcaContentSignerBuilder("SHA256withRSA")
                        .build(pair.getPrivate());
        assertConfigured("X509 certificate ContentSigner Signature",
                contentSignerSignature(certSigner).getProvider());

        final ContentSigner crlSigner =
                org.jruby.ext.openssl.X509CRL
                        .newJcaContentSignerBuilder("SHA256withRSA")
                        .build(pair.getPrivate());
        assertConfigured("X509 CRL ContentSigner Signature",
                contentSignerSignature(crlSigner).getProvider());

        final ContentSigner ocspSigner =
                OCSP.newJcaContentSignerBuilder("SHA256withRSA")
                        .build(pair.getPrivate());
        assertConfigured("OCSP ContentSigner Signature",
                contentSignerSignature(ocspSigner).getProvider());
    }

    @Test
    void crlVerificationUsesConfiguredSignatureProvider() throws Exception {
        final CertificateFactory factory = SecurityHelper.getCertificateFactory("X.509");
        final X509Certificate issuer;
        final X509CRL crl;
        try (FileInputStream in = new FileInputStream("src/test/ruby/x509/ec-ca.crt")) {
            issuer = (X509Certificate) factory.generateCertificate(in);
        }
        try (FileInputStream in = new FileInputStream("src/test/ruby/x509/ec-ca.crl")) {
            crl = (X509CRL) factory.generateCRL(in);
        }

        assertConfigured("CRL Signature", SecurityHelper.getSignature(crl.getSigAlgName()).getProvider());
        assertEquals(true, SecurityHelper.verify(crl, issuer.getPublicKey()));
        assertTrustedCertificateAuxTaggedSequencesUnwrapAndRoundTrip();
    }

    private void assertTrustedCertificateAuxTaggedSequencesUnwrapAndRoundTrip() throws Exception {
        final byte[] taggedBytes = new byte[] {
                (byte) 0xa0, 0x06, 0x30, 0x04, 0x06, 0x02, 0x2a, 0x03
        };
        try (ASN1InputStream input = new ASN1InputStream(taggedBytes)) {
            final ASN1TaggedObject tagged = (ASN1TaggedObject) input.readObject();
            assertTrue(tagged.getLoadedObject() instanceof ASN1TaggedObject,
                    "bc-fips getLoadedObject preserves the tagged wrapper");
            assertTrue(ASN1Sequence.getInstance(tagged, true) instanceof ASN1Sequence,
                    "explicit tagged-object access must unwrap the inner aux sequence");
        }

        final X509Certificate certificate;
        try (FileInputStream input = new FileInputStream("src/test/ruby/x509/ec-ca.crt")) {
            certificate = (X509Certificate)
                    SecurityHelper.getCertificateFactory("X.509").generateCertificate(input);
        }

        final byte[] auxBytes = new byte[] {
                0x30, 0x10,
                (byte) 0xa0, 0x06, 0x30, 0x04, 0x06, 0x02, 0x2a, 0x03,
                (byte) 0xa1, 0x06, 0x30, 0x04, 0x06, 0x02, 0x2a, 0x04
        };
        final byte[] trustedBytes = new byte[certificate.getEncoded().length + auxBytes.length];
        System.arraycopy(certificate.getEncoded(), 0, trustedBytes, 0, certificate.getEncoded().length);
        System.arraycopy(auxBytes, 0, trustedBytes, certificate.getEncoded().length, auxBytes.length);
        final String trustedPem = "-----BEGIN TRUSTED CERTIFICATE-----\n" +
                Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(trustedBytes) +
                "\n-----END TRUSTED CERTIFICATE-----\n";

        final X509AuxCertificate parsed = PEMInputOutput.readX509Aux(
                new BufferedReader(new StringReader(trustedPem)), null);
        assertNotNull(parsed);
        final StringWriter encoded = new StringWriter();
        PEMInputOutput.writeX509Aux(encoded, parsed);
        assertNotNull(PEMInputOutput.readX509Aux(
                new BufferedReader(new StringReader(encoded.toString())), null));
    }

    @Test
    void ecKeepOperationsUseConfiguredProvider() throws Exception {
        final KeyPairGenerator generator = SecurityHelper.getKeyPairGenerator("EC");
        assertConfigured("EC KeyPairGenerator", generator.getProvider());
        generator.initialize(new ECGenParameterSpec("P-256"));
        final KeyPair alice = generator.generateKeyPair();
        final KeyPair bob = generator.generateKeyPair();

        final KeyFactory factory = SecurityHelper.getKeyFactory("EC");
        assertConfigured("EC KeyFactory", factory.getProvider());
        assertNotNull(factory.generatePublic(new X509EncodedKeySpec(alice.getPublic().getEncoded())));

        final AlgorithmParameters parameters = SecurityHelper.getAlgorithmParameters("EC");
        assertConfigured("EC AlgorithmParameters", parameters.getProvider());
        parameters.init(new ECGenParameterSpec("P-256"));

        final Signature signer = SecurityHelper.getSignature("NONEwithECDSA");
        assertConfigured("NONEwithECDSA sign", signer.getProvider());
        signer.initSign(alice.getPrivate());
        final byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest("provider contract".getBytes("UTF-8"));
        signer.update(digest);
        final byte[] signature = signer.sign();

        final Signature verifier = SecurityHelper.getSignature("NONEwithECDSA");
        assertConfigured("NONEwithECDSA verify", verifier.getProvider());
        verifier.initVerify(alice.getPublic());
        verifier.update(digest);
        assertEquals(true, verifier.verify(signature));

        final KeyAgreement aliceAgreement = SecurityHelper.getKeyAgreement("ECDH");
        assertConfigured("ECDH KeyAgreement alice", aliceAgreement.getProvider());
        aliceAgreement.init(alice.getPrivate());
        aliceAgreement.doPhase(bob.getPublic(), true);

        final KeyAgreement bobAgreement = SecurityHelper.getKeyAgreement("ECDH");
        assertConfigured("ECDH KeyAgreement bob", bobAgreement.getProvider());
        bobAgreement.init(bob.getPrivate());
        bobAgreement.doPhase(alice.getPublic(), true);
        assertArrayEquals(aliceAgreement.generateSecret(), bobAgreement.generateSecret());
    }

    @Test
    void dhGenerationAndAgreementUseConfiguredProvider() throws Exception {
        final KeyPairGenerator generator = SecurityHelper.getKeyPairGenerator("DH");
        assertConfigured("DH KeyPairGenerator", generator.getProvider());
        generator.initialize(2048, SecurityHelper.getSecureRandom());
        final KeyPair alice = generator.generateKeyPair();
        final KeyPair bob = generator.generateKeyPair();

        final KeyFactory factory = SecurityHelper.getKeyFactory("DH");
        assertConfigured("DH KeyFactory", factory.getProvider());

        final KeyAgreement aliceAgreement = SecurityHelper.getKeyAgreement("DH");
        assertConfigured("DH KeyAgreement alice", aliceAgreement.getProvider());
        aliceAgreement.init(alice.getPrivate());
        aliceAgreement.doPhase(bob.getPublic(), true);

        final KeyAgreement bobAgreement = SecurityHelper.getKeyAgreement("DH");
        assertConfigured("DH KeyAgreement bob", bobAgreement.getProvider());
        bobAgreement.init(bob.getPrivate());
        bobAgreement.doPhase(alice.getPublic(), true);
        assertArrayEquals(aliceAgreement.generateSecret(), bobAgreement.generateSecret());

        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            runtime.evalScriptlet(
                    "alice = OpenSSL::PKey::DH.generate(2048, 2)\n" +
                    "bob = OpenSSL::PKey::DH.generate(2048, 2)\n" +
                    "raise 'provider group did not use g=2' unless alice.g.to_i == 2 && bob.g.to_i == 2\n" +
                    "raise 'provider did not select one named 2048-bit group' unless " +
                    "alice.p.num_bits == 2048 && alice.p == bob.p\n" +
                    "raise 'DH compute_key mismatch' unless " +
                    "alice.compute_key(bob.pub_key) == bob.compute_key(alice.pub_key)\n" +
                    "raise 'DH derive mismatch' unless alice.derive(bob) == bob.derive(alice)\n" +
                    "begin\n" +
                    "  OpenSSL::PKey::DH.generate(2048, 5)\n" +
                    "  raise 'requested generator was falsely reported as honored'\n" +
                    "rescue ArgumentError => e\n" +
                    "  raise unless e.message.include?('was not honored')\n" +
                    "end\n" +
                    "begin\n" +
                    "  OpenSSL::PKey::DH.generate(1024, 2)\n" +
                    "  raise 'unsupported DH size unexpectedly succeeded'\n" +
                    "rescue OpenSSL::PKey::DHError\n" +
                    "end\n");
            System.out.println("DH Ruby operations provider=" +
                    configuredProvider.getName() + ", group=ffdhe2048, g=2");
            System.out.println("DH requested g=5 rejected as not honored; size=1024 rejected");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void hkdfUsesFipsModuleAndMatchesRfc5869() throws Exception {
        assertNotNull(Class.forName(
                "org.bouncycastle.crypto.fips.FipsKDF", false,
                configuredProvider.getClass().getClassLoader()));
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final String result = runtime.evalScriptlet(
                    "ikm = ['0b' * 22].pack('H*')\n" +
                    "salt = ['000102030405060708090a0b0c'].pack('H*')\n" +
                    "info = ['f0f1f2f3f4f5f6f7f8f9'].pack('H*')\n" +
                    "OpenSSL::KDF.hkdf(ikm, salt: salt, info: info, " +
                    "length: 42, hash: 'SHA256').unpack1('H*')\n").asJavaString();
            assertEquals(
                    "3cb25f25faacd57a90434f64d0362f2a" +
                    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                    "34007208d5b887185865", result);
            System.out.println("FipsKDF RFC5869 SHA-256 OKM=" + result);
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void dsaReconstructionRequiresCompletePublicKey() throws Exception {
        assertConfigured("DSA KeyFactory",
                SecurityHelper.getKeyFactory("DSA").getProvider());
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            runtime.evalScriptlet(
                    "traditional = File.binread('src/test/ruby/fixtures/pkey/dsa1024')\n" +
                    "key = OpenSSL::PKey::DSA.new(traditional)\n" +
                    "data = 'complete DSA public key contract'\n" +
                    "sig = key.sign('SHA256', data)\n" +
                    "public_key = OpenSSL::PKey::DSA.new(key.public_to_pem)\n" +
                    "raise 'complete DSA public key verification failed' unless " +
                    "public_key.verify('SHA256', sig, data)\n" +
                    "begin\n" +
                    "  OpenSSL::PKey::DSA.new(File.binread('src/test/ruby/fixtures/pkey/dsa2048'))\n" +
                    "  raise 'x-only DSA PKCS8 unexpectedly derived y'\n" +
                    "rescue OpenSSL::PKey::DSAError => e\n" +
                    "  raise unless e.message.include?('deriving y from x is unavailable')\n" +
                    "end\n" +
                    "round_trip = OpenSSL::PKey::DSA.new(key.to_pem)\n" +
                    "raise 'complete DSA private export lost public y' unless " +
                    "round_trip.verify('SHA256', sig, data)\n");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void x509CrlAndOcspSigningReachConfiguredBuilders() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            runtime.evalScriptlet(
                    "key = OpenSSL::PKey::RSA.generate(2048)\n" +
                    "name = OpenSSL::X509::Certificate.new(" +
                    "File.binread('src/test/ruby/x509/ec-ca.crt')).subject\n" +
                    "cert = OpenSSL::X509::Certificate.new\n" +
                    "cert.version = 2\n" +
                    "cert.serial = 1\n" +
                    "cert.subject = cert.issuer = name\n" +
                    "cert.public_key = key.public_key\n" +
                    "cert.not_before = Time.now - 60\n" +
                    "cert.not_after = Time.now + 3600\n" +
                    "cert.sign(key, OpenSSL::Digest::SHA256.new)\n" +
                    "raise 'certificate verification failed' unless cert.verify(key)\n" +
                    "crl = OpenSSL::X509::CRL.new\n" +
                    "crl.version = 1\n" +
                    "crl.issuer = name\n" +
                    "crl.last_update = Time.now - 60\n" +
                    "crl.next_update = Time.now + 3600\n" +
                    "crl.sign(key, OpenSSL::Digest::SHA256.new)\n" +
                    "raise 'CRL verification failed' unless crl.verify(key)\n" +
                    "cid = OpenSSL::OCSP::CertificateId.new(cert, cert, OpenSSL::Digest::SHA256.new)\n" +
                    "request = OpenSSL::OCSP::Request.new.add_certid(cid)\n" +
                    "request.sign(cert, key, [])\n" +
                    "store = OpenSSL::X509::Store.new.add_cert(cert)\n" +
                    "raise 'OCSP verification failed' unless request.verify([], store)\n");
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    void rsaAndPssKeepOperationsUseConfiguredProvider() throws Exception {
        final KeyPairGenerator generator = SecurityHelper.getKeyPairGenerator("RSA");
        assertConfigured("RSA KeyPairGenerator", generator.getProvider());
        generator.initialize(2048);
        final KeyPair pair = generator.generateKeyPair();

        final KeyFactory factory = SecurityHelper.getKeyFactory("RSA");
        assertConfigured("RSA KeyFactory", factory.getProvider());
        assertNotNull(factory.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded())));

        final PSSParameterSpec pss = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        final byte[] message = "hashed RSA-PSS provider contract".getBytes("UTF-8");

        final Signature signer = SecurityHelper.getSignature("RSASSA-PSS");
        assertConfigured("RSASSA-PSS sign", signer.getProvider());
        signer.initSign(pair.getPrivate());
        signer.setParameter(pss);
        signer.update(message);
        final byte[] signature = signer.sign();

        final Signature verifier = SecurityHelper.getSignature("RSASSA-PSS");
        assertConfigured("RSASSA-PSS verify", verifier.getProvider());
        verifier.initVerify(pair.getPublic());
        verifier.setParameter(pss);
        verifier.update(message);
        assertEquals(true, verifier.verify(signature));
    }

    @Test
    void digestKeepOperationsUseConfiguredProvider() throws Exception {
        for (String algorithm : new String[] { "SHA-256", "SHA-384", "SHA-512" }) {
            final MessageDigest digest = SecurityHelper.getMessageDigest(algorithm);
            assertConfigured(algorithm + " MessageDigest", digest.getProvider());
            assertNotNull(digest.digest("provider contract".getBytes("UTF-8")));
        }
        assertHybridProviderAllowsAlgorithmsRestrictedByLogstashCore();
    }

    private void assertHybridProviderAllowsAlgorithmsRestrictedByLogstashCore() throws Exception {
        final KeyPairGenerator generator = SecurityHelper.getKeyPairGenerator("RSA");
        generator.initialize(2048, SecurityHelper.getSecureRandom());
        final KeyPair pair = generator.generateKeyPair();

        final Signature signature = SecurityHelper.getSignature("MD5withRSA");
        assertConfigured("MD5withRSA Signature", signature.getProvider());
        signature.initSign(pair.getPrivate());
        signature.update("hybrid mode".getBytes("UTF-8"));
        assertTrue(signature.sign().length > 0);

        final MessageDigest digest = SecurityHelper.getMessageDigest("MD5");
        assertConfigured("MD5 MessageDigest", digest.getProvider());
        assertEquals(16, digest.digest("hybrid mode".getBytes("UTF-8")).length);

        final Cipher cipher = SecurityHelper.getCipher("RC2/CBC/PKCS5Padding");
        assertConfigured("RC2/CBC Cipher", cipher.getProvider());
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(new byte[16], "RC2"), SecurityHelper.getSecureRandom());
        assertTrue(cipher.doFinal("hybrid mode".getBytes("UTF-8")).length > 0);

        final Mac mac = SecurityHelper.getMac("HmacMD5");
        assertConfigured("HmacMD5 Mac", mac.getProvider());
        mac.init(new SecretKeySpec(new byte[16], "HmacMD5"));
        assertEquals(16, mac.doFinal("hybrid mode".getBytes("UTF-8")).length);
    }

    @Test
    void pbkdf2KeepOperationsUseConfiguredProvider() throws Exception {
        for (String digest : new String[] { "SHA256", "SHA384", "SHA512" }) {
            final SecretKeyFactory factory =
                    SecurityHelper.getSecretKeyFactory("PBKDF2WithHmac" + digest);
            assertConfigured("PBKDF2WithHmac" + digest + " SecretKeyFactory",
                    factory.getProvider());
            final PBEKeySpec spec = new PBEKeySpec(
                    "password".toCharArray(), "salt".getBytes("UTF-8"), 1000, 256);
            assertNotNull(factory.generateSecret(spec).getEncoded());
        }
    }

    @Test
    void jrubyOpenSslKeepOperationsAndDropMessagesUnderStrictMode() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            runtime.evalScriptlet(
                    "data = 'provider contract'\n" +
                    "ec = OpenSSL::PKey::EC.generate('prime256v1')\n" +
                    "hash = OpenSSL::Digest.digest('SHA256', data)\n" +
                    "ec_sig = ec.dsa_sign_asn1(hash)\n" +
                    "raise 'ECDSA verify failed' unless ec.dsa_verify_asn1(hash, ec_sig)\n" +
                    "rsa = OpenSSL::PKey::RSA.generate(2048)\n" +
                    "pss = rsa.sign_pss('SHA256', data, salt_length: :digest, mgf1_hash: 'SHA256')\n" +
                    "raise 'PSS verify failed' unless rsa.verify_pss('SHA256', pss, data, " +
                    "salt_length: :digest, mgf1_hash: 'SHA256')\n" +
                    "key = OpenSSL::PKCS5.pbkdf2_hmac('password', 'salt', 1000, 32, 'SHA256')\n" +
                    "raise 'PBKDF2 failed' unless key.bytesize == 32\n" +
                    "begin\n" +
                    "  rsa.sign_raw('SHA256', hash, rsa_padding_mode: 'pss')\n" +
                    "  raise 'pre-hashed PSS unexpectedly succeeded'\n" +
                    "rescue NotImplementedError => e\n" +
                    "  raise unless e.message.include?('unsupported under FIPS')\n" +
                    "end\n" +
                    "begin\n" +
                    "  rsa.sign_pss('SHA256', data, salt_length: :auto, mgf1_hash: 'SHA256')\n" +
                    "  raise 'PSS auto salt unexpectedly succeeded'\n" +
                    "rescue ArgumentError => e\n" +
                    "  raise unless e.message.include?('unsupported under FIPS')\n" +
                    "end\n" +
                    "point = OpenSSL::PKey::EC::Point.allocate\n" +
                    "begin\n" +
                    "  point.add(nil)\n" +
                    "  raise 'EC point arithmetic unexpectedly succeeded'\n" +
                    "rescue NotImplementedError => e\n" +
                    "  raise unless e.message.include?('unsupported under FIPS')\n" +
                    "end\n");
        }
        finally {
            runtime.tearDown(false);
        }
    }
}
