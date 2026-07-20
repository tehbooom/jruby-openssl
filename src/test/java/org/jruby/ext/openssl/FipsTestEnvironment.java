package org.jruby.ext.openssl;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.Provider;
import java.security.Security;

/**
 * Shared FIPS test fixture: verifies non-FIPS BC is absent, registers bc-fips +
 * bctls-fips, and activates strict provider properties for embedded Ruby runs.
 */
public final class FipsTestEnvironment {

    private static Provider configuredProvider;
    private static Provider configuredSslProvider;
    private static int registrations;

    private FipsTestEnvironment() {
    }

    public static Provider configuredProvider() {
        return configuredProvider;
    }

    public static Provider configuredSslProvider() {
        return configuredSslProvider;
    }

    public static void assertNonFipsBcAbsent() {
        assertNull(Security.getProvider("BC"),
                "non-FIPS BC must not be registered in the FIPS test profile");
        try {
            Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            fail("non-FIPS BouncyCastleProvider must not be loadable");
        }
        catch (ClassNotFoundException expected) {
            // Required two-prong isolation: non-FIPS BC is absent.
        }
    }

    public static void registerConfiguredProviders() throws Exception {
        if (registrations++ > 0) return;

        assertNonFipsBcAbsent();

        final String pkixLocation = Class.forName(
                "org.bouncycastle.operator.jcajce.JcaContentSignerBuilder")
                .getProtectionDomain().getCodeSource().getLocation().toString();
        assertTrue(pkixLocation.contains("bcpkix-fips-2.0.7"),
                "FIPS contract requires the designated bcpkix-fips 2.0.7: " +
                        pkixLocation);
        System.out.println("configured FIPS PKIX module: " + pkixLocation);

        configuredProvider = (Provider) Class
                .forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider")
                .getDeclaredConstructor().newInstance();
        Security.addProvider(configuredProvider);
        configuredSslProvider = (Provider) Class
                .forName("org.bouncycastle.jsse.provider.BouncyCastleJsseProvider")
                .getDeclaredConstructor(String.class)
                .newInstance("fips:" + configuredProvider.getName());
        Security.addProvider(configuredSslProvider);

        System.setProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY,
                configuredProvider.getName() + ":2*");
        System.setProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY,
                configuredSslProvider.getName() + ":2*");
        System.setProperty("jruby.openssl.load.jars", "false");
        SecurityHelper.configureRequiredProvider();
        SecurityHelper.configureRequiredSslProvider();

        System.out.println("configured FIPS provider: " + configuredProvider.getName() +
                ":" + SecurityHelper.providerVersion(configuredProvider));
    }

    public static void removeConfiguredProviders() {
        if (registrations == 0 || --registrations > 0) return;

        System.clearProperty(SecurityHelper.REQUIRED_PROVIDER_PROPERTY);
        System.clearProperty(SecurityHelper.REQUIRED_SSL_PROVIDER_PROPERTY);
        System.clearProperty("jruby.openssl.load.jars");
        SecurityHelper.configureRequiredProvider();
        SecurityHelper.configureRequiredSslProvider();
        if (configuredSslProvider != null) Security.removeProvider(configuredSslProvider.getName());
        if (configuredProvider != null) Security.removeProvider(configuredProvider.getName());
        configuredSslProvider = null;
        configuredProvider = null;
    }
}
