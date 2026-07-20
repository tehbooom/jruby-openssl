/*
 * The MIT License
 *
 * Copyright 2014 Karol Bucek.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jruby.ext.openssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.GeneralSecurityException;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.SecureRandom;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.OperatorCreationException;

import org.jruby.ext.openssl.impl.pem.MiscPEMGeneratorHelper;
import org.jruby.ext.openssl.impl.pem.OpenSSLEVPPBE;
import org.jruby.ext.openssl.util.ByteArrayOutputStream;
//import org.bouncycastle.util.io.pem.PemReader;

import static org.jruby.ext.openssl.x509store.PEMInputOutput.getKeyFactory;

/**
 * PEM Utilities, for now mostly to replace {@link PEMHandler}.
 *
 * @author kares
 */
public abstract class PEMUtils {

    /*
    private static boolean bcPEMParser;
    private static Class<?> pemReaderImpl;

    private static Reader newPemReader(final Reader reader) {
        if ( pemReaderImpl == null ) {
            synchronized(BouncyCastlePEMHandler.class) {
                if ( pemReaderImpl == null ) {
                    try {
                        pemReaderImpl = Class.forName("org.bouncycastle.openssl.PEMParser");
                        bcPEMParser = true;
                    }
                    catch (ClassNotFoundException ex) {
                        pemReaderImpl = org.jruby.ext.openssl.impl.pem.PEMParser.class;
                    }
                }
            }
        }
        try {
            Constructor<? extends PemReader> constructor = (Constructor<? extends PemReader>)
                    pemReaderImpl.getConstructor(new Class[] { Reader.class });
            return constructor.newInstance(reader);
        }
        catch (NoSuchMethodException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
        //catch (InstantiationException e) {
        //}
        catch (InvocationTargetException e) {
            throw new IllegalStateException(e.getTargetException());
        }
        catch (Exception e) {
            if ( e instanceof RuntimeException ) throw (RuntimeException) e;
            throw new IllegalStateException(e);
        }
    }

    private static Object doInvoke(Object obj, String methodName, Class<?>[] paramTypes, Object... params)
        throws IOException {
        final Method method;
        try {
            method = obj.getClass().getDeclaredMethod(methodName, paramTypes);
            method.setAccessible(true);
            return method.invoke(obj, params);
        }
        catch (NoSuchMethodException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
        catch (InvocationTargetException e) {
            final Throwable target = e.getTargetException();
            if ( target instanceof IOException ) throw (IOException) target;
            if ( target instanceof RuntimeException ) throw (RuntimeException) target;
            throw new IllegalStateException(target);
        }
        catch (Exception e) {
            if ( e instanceof IOException ) throw (IOException) e;
            if ( e instanceof RuntimeException ) throw (RuntimeException) e;
            throw new IllegalStateException(e);
        }
    }

    */

    public static KeyPair readKeyPair(final Reader reader) throws IOException {
        return readKeyPair(reader, null);
    }

    public static KeyPair readKeyPair(final Reader reader, final char[] password) throws IOException {
        PEMKeyPair pemKeyPair = readInternal(reader, password);
        return toKeyPair(pemKeyPair);
    }

    static PEMKeyPair readInternal(final Reader reader, final char[] password) throws IOException {
        Object keyPair = new PEMParser(reader).readObject();
        if ( keyPair instanceof PEMEncryptedKeyPair) {
            return ((PEMEncryptedKeyPair) keyPair).decryptKeyPair(new PEMDecryptorImpl(password));
        }
        return (PEMKeyPair) keyPair;
    }

    private static KeyPair toKeyPair(final PEMKeyPair pemKeyPair) throws IOException {
        try {
            KeyFactory keyFactory = getKeyFactory( pemKeyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm() );
            return new KeyPair(
                keyFactory.generatePublic( new X509EncodedKeySpec( pemKeyPair.getPublicKeyInfo().getEncoded() ) ),
                keyFactory.generatePrivate( new PKCS8EncodedKeySpec( pemKeyPair.getPrivateKeyInfo().getEncoded() ) )
            );
        }
        catch (Exception e) {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    public static void writePEM(final Writer writer, final Object obj,
        final String algorithm, final char[] password) throws IOException {

        final PEMWriter pemWriter = new PEMWriter(writer);

        final SecureRandom random = SecurityHelper.isRequiredProviderMode() ?
                SecurityHelper.getSecureRandom() : new SecureRandom();

        pemWriter.writeObject(MiscPEMGeneratorHelper.newGenerator(obj, algorithm, password, random));
        pemWriter.flush();
    }

    public static void writePEM(final Writer writer, final Object obj) throws IOException {
        writePEM(writer, obj, null, null);
    }

    public static byte[] generatePKCS12(final Reader keyReader, final byte[] cert,
        final String aliasName, final char[] password)
        throws IOException, GeneralSecurityException {

        final Collection<? extends Certificate> certChain =
            SecurityHelper.getCertificateFactory("X.509").generateCertificates(new ByteArrayInputStream(cert));

        final PEMKeyPair pemKeyPair = readInternal(keyReader, null);
        final KeyFactory keyFactory = getKeyFactory( pemKeyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm() );
        Key privateKey = keyFactory.generatePrivate( new PKCS8EncodedKeySpec( pemKeyPair.getPrivateKeyInfo().getEncoded() ) );

        final KeyStore keyStore = SecurityHelper.getKeyStore("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry( aliasName, privateKey, null, certChain.toArray(new Certificate[certChain.size()]) );

        final ByteArrayOutputStream pkcs12Out = new ByteArrayOutputStream();
        keyStore.store(pkcs12Out, password == null ? new char[0] : password);

        return pkcs12Out.toByteArray();
    }

    private static class PEMDecryptorImpl implements PEMDecryptorProvider, PEMDecryptor {

        PEMDecryptorImpl(char[] password) { this.password = password; }

        private char[] password;
        private String dekAlgName;

        public PEMDecryptor get(String dekAlgName) throws OperatorCreationException {
            this.dekAlgName = dekAlgName;
            return this; // PEMDecryptor
        }

        public byte[] decrypt(byte[] keyBytes, byte[] iv) throws PEMException {
            return decrypt(keyBytes, password, dekAlgName, iv);
        }

        static byte[] decrypt(
            byte[] bytes,
            char[] password,
            String dekAlgName,
            byte[] iv)
            throws PEMException
        {
            return decrypt(SecurityHelper.getSecurityProvider(), bytes, password, dekAlgName, iv);
        }

        static byte[] decrypt(
            Provider provider,
            byte[] bytes,
            char[] password,
            String dekAlgName,
            byte[] iv)
            throws PEMException
        {
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
            String alg;
            String blockMode = "CBC";
            String padding = "PKCS5Padding";

            // Figure out block mode and padding.
            if (dekAlgName.endsWith("-CFB"))
            {
                blockMode = "CFB";
                padding = "NoPadding";
            }
            if (dekAlgName.endsWith("-ECB") ||
                "DES-EDE".equals(dekAlgName) ||
                "DES-EDE3".equals(dekAlgName))
            {
                blockMode = "ECB";
                paramSpec = null;
            }
            if (dekAlgName.endsWith("-OFB"))
            {
                blockMode = "OFB";
                padding = "NoPadding";
            }

            Key sKey;
            try {
                sKey = legacySecretKey(password, dekAlgName, iv);
            }
            catch (IOException | GeneralSecurityException e) {
                throw new PEMException(e.getMessage(), e);
            }
            alg = legacyCipherAlgorithm(dekAlgName);

            String transformation = alg + "/" + blockMode + "/" + padding;

            try
            {
                javax.crypto.Cipher cipher = SecurityHelper.getCipher(transformation);
                final int decryptMode = javax.crypto.Cipher.DECRYPT_MODE;

                if (paramSpec == null) // ECB block mode
                {
                    cipher.init(decryptMode, sKey);
                }
                else
                {
                    cipher.init(decryptMode, sKey, paramSpec);
                }
                return cipher.doFinal(bytes);
            }
            catch (Exception e)
            {
                throw new PEMException("exception using cipher - please check password and data.", e);
            }
        }

        private static SecretKey legacySecretKey(
            char[] password,
            String dekAlgName,
            byte[] iv)
            throws IOException, GeneralSecurityException, PEMException
        {
            if (dekAlgName.startsWith("DES-EDE"))
            {
                final String alg = "DESede";
                final boolean des2 = !dekAlgName.startsWith("DES-EDE3");
                return OpenSSLEVPPBE.secretKey(password, alg, 24, iv, des2);
            }
            if (dekAlgName.startsWith("DES-"))
            {
                return OpenSSLEVPPBE.secretKey(password, "DES", 8, iv);
            }
            if (dekAlgName.startsWith("BF-"))
            {
                return OpenSSLEVPPBE.secretKey(password, "Blowfish", 16, iv);
            }
            if (dekAlgName.startsWith("RC2-"))
            {
                int keyBits = 128;
                if (dekAlgName.startsWith("RC2-40-"))
                {
                    keyBits = 40;
                }
                else if (dekAlgName.startsWith("RC2-64-"))
                {
                    keyBits = 64;
                }
                return OpenSSLEVPPBE.secretKey(password, "RC2", keyBits / 8, iv);
            }
            if (dekAlgName.startsWith("AES-"))
            {
                byte[] salt = iv;
                if (salt.length > 8)
                {
                    salt = new byte[8];
                    System.arraycopy(iv, 0, salt, 0, 8);
                }

                int keyBits;
                if (dekAlgName.startsWith("AES-128-"))
                {
                    keyBits = 128;
                }
                else if (dekAlgName.startsWith("AES-192-"))
                {
                    keyBits = 192;
                }
                else if (dekAlgName.startsWith("AES-256-"))
                {
                    keyBits = 256;
                }
                else
                {
                    throw new PEMException("unknown AES encryption with private key");
                }
                return OpenSSLEVPPBE.secretKey(password, "AES", keyBits / 8, salt);
            }
            throw new PEMException("unknown encryption with private key");
        }

        private static String legacyCipherAlgorithm(final String dekAlgName) throws PEMException {
            if (dekAlgName.startsWith("DES-EDE")) return "DESede";
            if (dekAlgName.startsWith("DES-")) return "DES";
            if (dekAlgName.startsWith("BF-")) return "Blowfish";
            if (dekAlgName.startsWith("RC2-")) return "RC2";
            if (dekAlgName.startsWith("AES-")) return "AES";
            throw new PEMException("unknown encryption with private key");
        }

    }

}
