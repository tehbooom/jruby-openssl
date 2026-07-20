package org.jruby.ext.openssl.impl.pem;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jruby.ext.openssl.SecurityHelper;

/**
 * OpenSSL legacy PEM encryption KDF (EVP_BytesToKey with MD5, one iteration).
 * Replaces {@code org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator}
 * so encrypted legacy PEM does not depend on bcprov-internal crypto classes absent
 * from the bc-fips classpath.
 */
public final class OpenSSLEVPPBE {

    private static final String FIPS_REJECTION =
            "legacy Proc-Type encrypted PEM (MD5 EVP_BytesToKey) is unsupported under FIPS";

    private OpenSSLEVPPBE() {
    }

    public static void rejectLegacyEncryptedPemUnderFips() throws IOException {
        if (SecurityHelper.isRequiredProviderMode()) {
            throw new IOException(FIPS_REJECTION);
        }
    }

    public static byte[] pkcs5PasswordToBytes(final char[] password) {
        if (password == null) return new byte[0];
        final byte[] bytes = new byte[password.length];
        for (int i = 0; i < password.length; i++) {
            bytes[i] = (byte) password[i];
        }
        return bytes;
    }

    /**
     * @param keyLenBytes desired key length in bytes (not bits)
     */
    public static byte[] deriveKey(final char[] password, final byte[] salt, final int keyLenBytes)
            throws GeneralSecurityException, IOException {
        rejectLegacyEncryptedPemUnderFips();
        return evpBytesToKeyMD5(pkcs5PasswordToBytes(password), salt, keyLenBytes);
    }

    public static SecretKey secretKey(final char[] password, final String algorithm,
            final int keyLenBytes, final byte[] salt)
            throws GeneralSecurityException, IOException {
        return secretKey(password, algorithm, keyLenBytes, salt, false);
    }

    public static SecretKey secretKey(final char[] password, final String algorithm,
            final int keyLenBytes, final byte[] salt, final boolean des2)
            throws GeneralSecurityException, IOException {
        byte[] key = deriveKey(password, salt, keyLenBytes);
        if (des2 && key.length >= 24) {
            System.arraycopy(key, 0, key, 16, 8);
        }
        return new SecretKeySpec(key, algorithm);
    }

    static byte[] evpBytesToKeyMD5(final byte[] password, byte[] salt, final int targetLenBytes)
            throws NoSuchAlgorithmException {
        if (salt != null && salt.length > 8) {
            final byte[] salt8 = new byte[8];
            System.arraycopy(salt, 0, salt8, 0, 8);
            salt = salt8;
        }

        final MessageDigest md = MessageDigest.getInstance("MD5");
        final byte[] derived = new byte[targetLenBytes];
        byte[] digest = null;
        int offset = 0;
        while (offset < targetLenBytes) {
            md.reset();
            if (digest != null) md.update(digest);
            md.update(password);
            if (salt != null) md.update(salt);
            digest = md.digest();
            final int copy = Math.min(digest.length, targetLenBytes - offset);
            System.arraycopy(digest, 0, derived, offset, copy);
            offset += copy;
        }
        return derived;
    }
}
