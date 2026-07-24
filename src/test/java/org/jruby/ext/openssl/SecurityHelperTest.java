
package org.jruby.ext.openssl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.PEMException;
import org.jruby.ext.openssl.impl.EVP;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import org.jruby.Ruby;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author kares
 */
public class SecurityHelperTest {

    // @BeforeClass
    public static void setBouncyCastleProvider() {
        SecurityHelper.setBouncyCastleProvider();
    }

    private Provider savedProvider;
    private Provider savedRequiredProvider;
    private Provider savedRequiredSslProvider;
    private Provider savedJsseProvider;
    private boolean savedSetJsseProvider;
    private String savedRequiredProviderProperty;
    private String savedRequiredSslProviderProperty;

    @BeforeEach
    public void saveSecurityProvider() {
        savedProvider = SecurityHelper.getSecurityProvider();
        savedRequiredProvider = SecurityHelper.requiredProvider;
        savedRequiredSslProvider = SecurityHelper.requiredSslProvider;
        savedJsseProvider = SecurityHelper.jsseProvider;
        savedSetJsseProvider = SecurityHelper.setJsseProvider;
        savedRequiredProviderProperty =
                System.getProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY);
        savedRequiredSslProviderProperty =
                System.getProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY);
        SecurityHelper.requiredProvider = null;
        System.clearProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY);
        System.clearProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY);
        SecurityHelper.configureRequiredSslProvider();
    }

    @AfterEach
    public void restoreSecurityProvider() {
        SecurityHelper.securityProvider = savedProvider;
        SecurityHelper.requiredProvider = savedRequiredProvider;
        SecurityHelper.requiredSslProvider = savedRequiredSslProvider;
        SecurityHelper.jsseProvider = savedJsseProvider;
        SecurityHelper.setJsseProvider = savedSetJsseProvider;
        if (savedRequiredProviderProperty == null) {
            System.clearProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY);
        } else {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, savedRequiredProviderProperty);
        }
        if (savedRequiredSslProviderProperty == null) {
            System.clearProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY);
        } else {
            System.setProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY, savedRequiredSslProviderProperty);
        }
        SecurityHelper.configureRequiredSslProvider();
    }

    private static final class EmptyProvider extends Provider {
        private EmptyProvider(final String name, final double version) {
            super(name, version, "provider contract test");
        }
    }

    private static Provider builderProvider(final Object builder) throws Exception {
        final Field operatorHelperField = builder.getClass().getDeclaredField("helper");
        operatorHelperField.setAccessible(true);
        final Object operatorHelper = operatorHelperField.get(builder);

        final Field jcaHelperField = operatorHelper.getClass().getDeclaredField("helper");
        jcaHelperField.setAccessible(true);
        final Object jcaHelper = jcaHelperField.get(operatorHelper);
        try {
            return (Provider) jcaHelper.getClass().getMethod("getProvider").invoke(jcaHelper);
        }
        catch (NoSuchMethodException ex) {
            final String providerName =
                    (String) jcaHelper.getClass().getMethod("getProviderName").invoke(jcaHelper);
            return Security.getProvider(providerName);
        }
    }

    public static final class TestSSLContextSpi extends SSLContextSpi {
        @Override
        protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr)
                throws KeyManagementException {
        }

        @Override
        protected SSLSocketFactory engineGetSocketFactory() { return null; }

        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() { return null; }

        @Override
        protected SSLEngine engineCreateSSLEngine() { return null; }

        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) { return null; }

        @Override
        protected SSLSessionContext engineGetServerSessionContext() { return null; }

        @Override
        protected SSLSessionContext engineGetClientSessionContext() { return null; }

        @Override
        protected SSLParameters engineGetDefaultSSLParameters() { return new SSLParameters(); }

        @Override
        protected SSLParameters engineGetSupportedSSLParameters() { return new SSLParameters(); }
    }

    @Test
    public void requiredProviderGlobMatchesReportedVersion() {
        assertTrue(SecurityHelper.globMatches("2*", "2.0001"));
        assertTrue(SecurityHelper.globMatches("2.*.1", "2.0.1"));
        assertTrue(SecurityHelper.globMatches("*", "anything"));
        assertFalse(SecurityHelper.globMatches("3*", "2.0001"));
        assertFalse(SecurityHelper.globMatches("2.0", "2.0001"));
        assertFalse(SecurityHelper.globMatches("2.+", "2.0"));
    }

    @Test
    public void resolvesDeploymentRegisteredRequiredProvider() {
        final Provider provider = new EmptyProvider("JOSSL_TEST_REQUIRED", 2.0001);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY,
                    provider.getName() + ":2*");
            SecurityHelper.configureRequiredProvider();
            assertSame(provider, SecurityHelper.getSecurityProvider());
            assertEquals(provider.getName(), SecurityHelper.requiredProvider.getName());
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void missingRequiredProviderFailsLoud() {
        System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, "JOSSL_MISSING:2*");
        final Ruby runtime = Ruby.newInstance();
        try {
            final IllegalStateException error = assertThrows(
                    IllegalStateException.class, () -> OpenSSL.createOpenSSL(runtime));
            assertTrue(error.getMessage().contains("JOSSL_MISSING:2*"));
            assertTrue(error.getMessage().contains("was not found"));
        }
        finally {
            runtime.tearDown(false);
        }
    }

    @Test
    public void mismatchedRequiredProviderVersionFailsLoud() {
        final Provider provider = new EmptyProvider("JOSSL_TEST_VERSION", 2.0001);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY,
                    provider.getName() + ":3*");
            final Ruby runtime = Ruby.newInstance();
            try {
                final IllegalStateException error = assertThrows(
                        IllegalStateException.class, () -> OpenSSL.createOpenSSL(runtime));
                assertTrue(error.getMessage().contains(provider.getName() + ":3*"));
                assertTrue(error.getMessage().contains(
                        provider.getName() + ":" + SecurityHelper.providerVersion(provider)));
            }
            finally {
                runtime.tearDown(false);
            }
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void requiredProviderNeverFallsBackForUnsupportedAlgorithm() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            assertNotNull(java.security.MessageDigest.getInstance("SHA-256"));
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getMessageDigest("SHA-256"));
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void requiredProviderNeverFallsBackForKeyStore() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_KEYSTORE_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            assertNotNull(java.security.KeyStore.getInstance("JKS"));
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();
            assertThrows(KeyStoreException.class, () -> SecurityHelper.getKeyStore("JKS"));
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void strictOcspBuildersIgnoreRegisteredNonFipsBc() throws Exception {
        boolean fipsEnvironmentRegistered = false;
        try {
            Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
            FipsTestEnvironment.registerConfiguredProviders();
            fipsEnvironmentRegistered = true;
        }
        catch (ClassNotFoundException ignored) {
            // The regular test classpath does not include BCFIPS.
        }

        final java.util.function.Function<Object, Provider> configuredBuilderProvider = builder -> {
            try {
                final Field operatorHelperField = builder.getClass().getDeclaredField("helper");
                operatorHelperField.setAccessible(true);
                final Object operatorHelper = operatorHelperField.get(builder);
                final Field jcaHelperField = operatorHelper.getClass().getDeclaredField("helper");
                jcaHelperField.setAccessible(true);
                final Object jcaHelper = jcaHelperField.get(operatorHelper);
                final Field providerField = jcaHelper.getClass().getDeclaredField("provider");
                providerField.setAccessible(true);
                return (Provider) providerField.get(jcaHelper);
            }
            catch (ReflectiveOperationException ex) {
                throw new IllegalStateException(ex);
            }
        };

        final Provider provider = new EmptyProvider("JOSSL_TEST_OCSP_REQUIRED", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();

            assertSame(provider, configuredBuilderProvider.apply(
                    OCSP.newJcaContentSignerBuilder("SHA256withRSA")));
            assertSame(provider, configuredBuilderProvider.apply(
                    OCSP.newJcaContentVerifierProviderBuilder()));
            assertSame(provider, configuredBuilderProvider.apply(
                    OCSP.newJcaDigestCalculatorProviderBuilder()));
            assertSame(provider, configuredBuilderProvider.apply(
                    X509Cert.newJcaContentSignerBuilder("SHA256withRSA")));
            assertSame(provider, configuredBuilderProvider.apply(
                    org.jruby.ext.openssl.X509CRL
                            .newJcaContentSignerBuilder("SHA256withRSA")));
        }
        finally {
            Security.removeProvider(provider.getName());
            if (fipsEnvironmentRegistered) {
                FipsTestEnvironment.removeConfiguredProviders();
            }
        }
    }

    @Test
    public void requiredProvidersNeverFallbackAcrossWrapperAudit() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_WRAPPER_AUDIT", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            System.setProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();
            SecurityHelper.configureRequiredSslProvider();

            assertThrows(CertificateException.class,
                    () -> SecurityHelper.getCertificateFactory("X.509"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getKeyFactory("RSA"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getAlgorithmParameters("EC"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getKeyPairGenerator("RSA"));
            assertThrows(KeyStoreException.class,
                    () -> SecurityHelper.getKeyStore("JKS"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getMessageDigest("SHA-256"));
            assertThrows(IllegalStateException.class, SecurityHelper::getSecureRandom);
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getCipher("AES"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getSignature("SHA256withRSA"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getMac("HmacSHA256"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getKeyGenerator("AES"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getKeyAgreement("DH"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getSecretKeyFactory("PBKDF2WithHmacSHA256"));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getSSLContext("TLS"));
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void requiredSslProviderRoutesByRegisteredNameAndFailsAfterRemoval() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_JSSE", 2.0001);
        provider.put("SSLContext.TLS", TestSSLContextSpi.class.getName());
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY,
                    provider.getName() + ":2*");
            SecurityHelper.configureRequiredSslProvider();
            assertSame(provider, SecurityHelper.getSSLContext("TLS").getProvider());

            Security.removeProvider(provider.getName());
            assertThrows(IllegalStateException.class, () -> SecurityHelper.getSSLContext("TLS"));
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void requiredSslProviderNeverFallsBackForUnsupportedProtocol() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_JSSE_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            assertNotNull(SSLContext.getInstance("TLS"));
            System.setProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredSslProvider();
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.getSSLContext("TLS"));
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void strictJceWithoutRequiredSslProviderFailsLoud() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_JCE_ONLY", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            System.clearProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY);
            SecurityHelper.configureRequiredProvider();
            SecurityHelper.configureRequiredSslProvider();

            final IllegalStateException error = assertThrows(
                    IllegalStateException.class, () -> SecurityHelper.getSSLContext("TLS"));
            assertTrue(error.getMessage().contains(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY));
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void strictLegacyBcjsseLookupNeverConstructsUnregisteredProvider() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_JCE_LEGACY_JSSE", 1.0);
        Security.addProvider(provider);
        final Provider registeredBcjsse = Security.getProvider("BCJSSE");
        if (registeredBcjsse != null) Security.removeProvider("BCJSSE");
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();
            SecurityHelper.jsseProvider = null;
            SecurityHelper.setJsseProvider = true;

            final Method lookup = SecurityHelper.class.getDeclaredMethod(
                    "getJsseProvider", String.class);
            lookup.setAccessible(true);
            assertNull(lookup.invoke(null, "BCJSSE"),
                    "strict legacy lookup must not construct an unregistered BCJSSE provider");
        }
        finally {
            if (registeredBcjsse != null) Security.addProvider(registeredBcjsse);
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void missingRequiredSslProviderFailsBeforeLegacyInstantiation() {
        System.setProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY, "JOSSL_MISSING_JSSE:2*");
        final IllegalStateException error = assertThrows(
                IllegalStateException.class, SecurityHelper::configureRequiredSslProvider);
        assertTrue(error.getMessage().contains("JOSSL_MISSING_JSSE:2*"));
        assertTrue(error.getMessage().contains("was not found"));
    }

    @Test
    public void unsetRequiredSslProviderKeepsDefaultSslBehavior() throws Exception {
        System.clearProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY);
        SecurityHelper.configureRequiredSslProvider();
        assertEquals(SSLContext.getInstance("TLS").getProvider().getName(),
                SecurityHelper.getSSLContext("TLS").getProvider().getName());
    }

    @Test
    public void strictCrlVerificationNeverUsesBcOrJdkFallback() throws Exception {
        Provider selectedProvider;
        boolean fipsEnvironmentRegistered = false;
        try {
            Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
            FipsTestEnvironment.registerConfiguredProviders();
            selectedProvider = FipsTestEnvironment.configuredProvider();
            fipsEnvironmentRegistered = true;
        }
        catch (ClassNotFoundException ignored) {
            // The regular test classpath uses the platform X.509 provider.
            selectedProvider = CertificateFactory.getInstance("X.509").getProvider();
        }

        final Provider configuredProvider = selectedProvider;
        final CertificateFactory factory =
                CertificateFactory.getInstance("X.509", configuredProvider);
        final X509Certificate issuer;
        final X509CRL firstCrl;
        final X509CRL secondCrl;
        try (FileInputStream in = new FileInputStream("src/test/ruby/x509/ec-ca.crt")) {
            issuer = (X509Certificate) factory.generateCertificate(in);
        }
        try (FileInputStream in = new FileInputStream("src/test/ruby/x509/ec-ca.crl")) {
            firstCrl = (X509CRL) factory.generateCRL(in);
        }
        try (FileInputStream in = new FileInputStream("src/test/ruby/x509/ec-ca.crl")) {
            secondCrl = (X509CRL) factory.generateCRL(in);
        }
        if (fipsEnvironmentRegistered) {
            firstCrl.verify(issuer.getPublicKey(), configuredProvider);
            secondCrl.verify(issuer.getPublicKey(), configuredProvider);
        }
        else {
            firstCrl.verify(issuer.getPublicKey());
            secondCrl.verify(issuer.getPublicKey());
        }

        final Provider provider = new EmptyProvider("JOSSL_TEST_CRL_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.verify(firstCrl, issuer.getPublicKey()));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> SecurityHelper.verify(secondCrl, issuer.getPublicKey()));
        }
        finally {
            Security.removeProvider(provider.getName());
            if (fipsEnvironmentRegistered) {
                FipsTestEnvironment.removeConfiguredProviders();
            }
        }
    }

    @Test
    public void strictModeNeverInstantiatesNonFipsBcProvider() throws Exception {
        try {
            Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
        }
        catch (ClassNotFoundException ignored) {
            // The regular test classpath does not include BCFIPS.
            return;
        }

        boolean fipsEnvironmentRegistered = false;
        try {
            FipsTestEnvironment.registerConfiguredProviders();
            fipsEnvironmentRegistered = true;

            assertTrue(SecurityHelper.isRequiredProviderMode());
            assertNull(Security.getProvider("BC"),
                    "strict mode must not register non-FIPS BC provider");
            assertNull(SecurityHelper.securityProvider,
                    "strict mode must not instantiate non-FIPS BC security provider");
            assertSame(FipsTestEnvironment.configuredProvider(),
                    SecurityHelper.getSecurityProvider());
        }
        finally {
            if (fipsEnvironmentRegistered) {
                FipsTestEnvironment.removeConfiguredProviders();
            }
        }
    }

    @Test
    public void strictEvpSha1ThrowsForMissingDigestInRequiredProviderMode() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_EVP_SHA1_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();
            assertThrows(NoSuchAlgorithmException.class, EVP::sha1);
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void strictPemPublicKeyReadThrowsForMissingKeyFactory() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_PEM_KEY_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();
            final IOException error = assertThrows(IOException.class,
                    () -> PEMInputOutput.readRSAPublicKey(
                            new StringReader(new String(java.nio.file.Files.readAllBytes(
                                    java.nio.file.Paths.get(
                                            "src/test/ruby/fixtures/pkey/custom/rsa-2048-public.pem")))),
                            null));
            assertTrue(error.getCause() instanceof PEMException);
            assertTrue(error.getCause().getMessage()
                    .contains("Algorithm not available from required provider"));
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void strictEcParamSpecNeverFallsBackToBcTables() throws Exception {
        final Provider provider = new EmptyProvider("JOSSL_TEST_EC_PARAMS_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();

            final Class<?> bcInternal = Class.forName("org.jruby.ext.openssl.PKeyEC$BCInternal");
            final Method getParamSpec = bcInternal.getDeclaredMethod("getParamSpec", String.class);
            getParamSpec.setAccessible(true);

            final java.lang.reflect.InvocationTargetException error =
                    assertThrows(java.lang.reflect.InvocationTargetException.class,
                            () -> getParamSpec.invoke(null, "prime256v1"));
            assertTrue(error.getCause() instanceof IllegalStateException);
            assertTrue(error.getCause().getMessage()
                    .contains("EC parameters unavailable from required provider"));
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void strictCertificateVerificationPinsRequiredProvider() throws Exception {
        final X509Certificate issuer;
        try (FileInputStream in = new FileInputStream("src/test/ruby/x509/ec-ca.crt")) {
            issuer = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        }

        final boolean[] oneArgumentVerifyCalled = { false };
        final String[] verifiedProviderName = { null };
        final X509Certificate certificate = new X509AuxCertificate(issuer) {
            @Override
            public void verify(final PublicKey key) {
                oneArgumentVerifyCalled[0] = true;
            }

            @Override
            public void verify(final PublicKey key, final String providerName) {
                verifiedProviderName[0] = providerName;
            }
        };

        final Provider provider = new EmptyProvider("JOSSL_TEST_CERT_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();

            assertTrue(SecurityHelper.verify(certificate, issuer.getPublicKey()));
            assertEquals(provider.getName(), verifiedProviderName[0]);
            assertFalse(oneArgumentVerifyCalled[0]);
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void strictAuxCertificateVerificationIgnoresSuppliedProvider() throws Exception {
        final X509Certificate issuer;
        try (FileInputStream in = new FileInputStream("src/test/ruby/x509/ec-ca.crt")) {
            issuer = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        }

        final boolean[] oneArgumentVerifyCalled = { false };
        final String[] verifiedProviderName = { null };
        final X509Certificate delegate = new X509AuxCertificate(issuer) {
            @Override
            public void verify(final PublicKey key) {
                oneArgumentVerifyCalled[0] = true;
            }

            @Override
            public void verify(final PublicKey key, final String providerName) {
                verifiedProviderName[0] = providerName;
            }
        };
        final X509AuxCertificate certificate = new X509AuxCertificate(delegate);

        final Provider provider = new EmptyProvider("JOSSL_TEST_AUX_CERT_EMPTY", 1.0);
        Security.addProvider(provider);
        try {
            System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY, provider.getName());
            SecurityHelper.configureRequiredProvider();

            certificate.verify(issuer.getPublicKey(), "JOSSL_WRONG_PROVIDER");
            assertEquals(provider.getName(), verifiedProviderName[0]);
            assertFalse(oneArgumentVerifyCalled[0]);
        }
        finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void unsetRequiredProviderKeepsDefaultProviderBehavior() throws Exception {
        System.clearProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY);
        SecurityHelper.configureRequiredProvider();
        assertNull(SecurityHelper.requiredProvider);
        assertNotNull(SecurityHelper.getMessageDigest("SHA-256"));
    }

    public void disableSecurityProvider() {
        SecurityHelper.securityProvider = null;
        SecurityHelper.setBouncyCastleProvider = false;
    }

    @Test
    public void usesBouncyCastleSecurityProviderByDefault() {
        assertNotNull(SecurityHelper.getSecurityProvider());
        assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider",
            SecurityHelper.getSecurityProvider().getClass().getName()
        );
    }

    @Test
    public void allowsToSetSecurityProvider() {
        final Provider provider;
        try {
            Class providerClass = Class.forName("sun.security.provider.Sun");
            provider = (Provider) providerClass.newInstance();
        }
        catch (Exception e) {
            System.out.println("allowsToSetSecurityProvider() skipped due: " + e);
            return;
        }
        SecurityHelper.setSecurityProvider(provider);

        assertSame(provider, SecurityHelper.getSecurityProvider());
    }

    @Test
    public void doesNotRegisterBouncyCastleSecurityProviderByDefault() {
        SecurityHelper.getSecurityProvider();
        assertNull(java.security.Security.getProvider("BC"));
    }

    @Test
    public void registersSecurityProviderWhenRequested() {
        SecurityHelper.setRegisterProvider(true);
        try {
            SecurityHelper.getSecurityProvider();
            assertNotNull(java.security.Security.getProvider("BC"));
        }
        finally {
            java.security.Security.removeProvider("BC");
            SecurityHelper.setRegisterProvider(false);
        }
    }

    // Standart java.security

    @Test
    public void testGetKeyFactory() throws Exception {
        assertNotNull( SecurityHelper.getKeyFactory("RSA") );
        assertNotNull( SecurityHelper.getKeyFactory("DSA") );
    }

    @Test
    public void testGetKeyFactoryWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getKeyFactory("RSA") );
        assertNotNull( SecurityHelper.getKeyFactory("DSA") );
    }

    @Test
    public void testGetKeyFactoryThrows() throws Exception {
        try {
            SecurityHelper.getKeyFactory("USA");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getKeyFactory("USA", savedProvider);
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    //

    @Test
    public void testGetKeyPairGenerator() throws Exception {
        assertNotNull( SecurityHelper.getKeyPairGenerator("RSA") );
        assertNotNull( SecurityHelper.getKeyPairGenerator("DSA") );

        assertNotNull( SecurityHelper.getKeyPairGenerator("RSA", savedProvider) );
    }

    @Test
    public void testGetKeyPairGeneratorWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getKeyPairGenerator("RSA") );
        assertNotNull( SecurityHelper.getKeyPairGenerator("DSA") );
    }

    @Test
    public void testGetKeyPairGeneratorThrows() throws Exception {
        try {
            SecurityHelper.getKeyPairGenerator("USA");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getKeyPairGenerator("USA", savedProvider);
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    //

    @Test
    public void testGetKeyStore() throws Exception {
        assertNotNull( SecurityHelper.getKeyStore("PKCS12") );

        assertNotNull( SecurityHelper.getKeyStore("PKCS12", savedProvider) );
    }

    @Test
    public void testGetKeyStoreWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getKeyStore("PKCS12") );
    }

    @Test
    public void testGetKeyStoreThrows() throws Exception {
        try {
            SecurityHelper.getKeyStore("PKCS42");
            fail();
        }
        catch (KeyStoreException e) {
            // OK
        }
        try {
            SecurityHelper.getKeyStore("PKCS42", savedProvider);
            fail();
        }
        catch (KeyStoreException e) {
            // OK
        }
    }

    //

    @Test
    public void testGetMessageDigest() throws Exception {
        assertNotNull( SecurityHelper.getMessageDigest("MD5") );
        assertNotNull( SecurityHelper.getMessageDigest("SHA-1") );

        assertNotNull( SecurityHelper.getMessageDigest("MD5", savedProvider) );
    }

    @Test
    public void testGetMessageDigestWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getMessageDigest("MD5") );
        assertNotNull( SecurityHelper.getMessageDigest("SHA-1") );
    }

    @Test
    public void testGetMessageDigestThrows() throws Exception {
        try {
            SecurityHelper.getMessageDigest("XXL");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getMessageDigest("XXL", savedProvider);
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    //

    @Test
    public void testGetSignature() throws Exception {
        assertNotNull( SecurityHelper.getSignature("NONEwithRSA") );

        assertNotNull( SecurityHelper.getSignature("NONEwithRSA", savedProvider) );
    }

    @Test
    public void testGetSignatureWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getSignature("NONEwithRSA") );
    }

    @Test
    public void testGetSignatureThrows() throws Exception {
        try {
            SecurityHelper.getSignature("SOMEwithRSA");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getSignature("SOMEwithRSA", savedProvider);
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    //

    @Test
    public void testGetCertificateFactory() throws Exception {
        assertNotNull( SecurityHelper.getCertificateFactory("X.509") );

        assertNotNull( SecurityHelper.getCertificateFactory("X.509", savedProvider) );
    }

    @Test
    public void testGetCertificateFactoryWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getCertificateFactory("X.509") );
    }

    @Test
    public void testGetCertificateFactoryThrows() throws Exception {
        try {
            SecurityHelper.getCertificateFactory("X.510");
            fail();
        }
        catch (CertificateException e) {
            // OK
        }
        try {
            SecurityHelper.getCertificateFactory("X.510", savedProvider);
            fail();
        }
        catch (CertificateException e) {
            // OK
        }
    }

    @Test
    public void testGetSecureRandom() throws Exception {
        assertNotNull( SecurityHelper.getSecureRandom() );
    }

    // JCE

    @Test
    public void testGetCipher() throws Exception {
        assertNotNull( SecurityHelper.getCipher("DES") );
        assertNotNull( SecurityHelper.getCipher("AES") );

        assertNotNull( SecurityHelper.getCipher("DES/CBC/PKCS5Padding") );
    }

    @Test
    public void testGetCipherBC() throws Exception {
        assertNotNull( SecurityHelper.getCipher("AES", savedProvider) );

        assertNotNull( SecurityHelper.getCipher("DES/CBC/PKCS5Padding", savedProvider) );
    }

    @Test
    public void testGetCipherWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getCipher("DES") );
        assertNotNull( SecurityHelper.getCipher("AES") );
    }

    @Test
    public void testGetSecretKeyFactory() throws Exception {
        assertNotNull( SecurityHelper.getSecretKeyFactory("DES") );

        assertNotNull( SecurityHelper.getSecretKeyFactory("DESede", savedProvider) );
    }

    @Test
    public void testGetSecretKeyFactoryWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getSecretKeyFactory("DES") );
        assertNotNull( SecurityHelper.getSecretKeyFactory("DESede") );
    }

    @Test
    public void testGetSecretKeyFactoryThrows() throws Exception {
        try {
            SecurityHelper.getSecretKeyFactory("MESS");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getSecretKeyFactory("MESS", savedProvider);
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    //

    @Test
    public void testGetMac() throws Exception {
        assertNotNull( SecurityHelper.getMac("HmacMD5") );
        assertNotNull( SecurityHelper.getMac("HmacSHA1") );

        assertNotNull( SecurityHelper.getMac("HmacMD5", savedProvider) );
    }

    @Test
    public void testGetMacWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getMac("HMacMD5") );
    }

    @Test
    public void testGetMacThrows() throws Exception {
        try {
            SecurityHelper.getMac("HmacMDX");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getMac("HmacMDX", savedProvider);
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    //

    @Test
    public void testGetKeyGenerator() throws Exception {
        assertNotNull( SecurityHelper.getKeyGenerator("AES") );

        assertNotNull( SecurityHelper.getKeyGenerator("AES", savedProvider) );
    }

    @Test
    public void testGetKeyGeneratorWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getKeyGenerator("AES") );
    }

    @Test
    public void testGetKeyGeneratorThrows() throws Exception {
        try {
            SecurityHelper.getKeyGenerator("AMD");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getKeyGenerator("AMD", savedProvider);
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    @Test
    public void testCertificateFactoryProviderStaysConstant() throws Exception {
        Provider[] registeredProviders = Security.getProviders();

        try {
            // clear previous providers
            for (Provider provider : registeredProviders) Security.removeProvider(provider.getName());

            CertificateFactory certFactory1 = SecurityHelper.getCertificateFactory("X.509");
            CertificateFactory certFactory2 = SecurityHelper.getCertificateFactory("X.509");

            assertSame(certFactory1.getProvider(), certFactory2.getProvider());
        } finally {
            // clear any added by the test
            for (Provider provider : Security.getProviders()) Security.removeProvider(provider.getName());

            // restore previous providers
            for (Provider provider : registeredProviders) Security.addProvider(provider);
        }
    }

}
