/*
 * The MIT License
 *
 * Copyright (c) 2018 Karol Bucek LTD.
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

import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import javax.crypto.Mac;

import org.jruby.*;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.Utils.extractKeywordArgs;

/**
 * Provides functionality of various KDFs (key derivation function).
 *
 * @author kares
 */
@JRubyModule(name = "OpenSSL::KDF")
public class KDF {

    static void createKDF(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        RubyModule KDF = OpenSSL.defineModuleUnder("KDF");
        KDF.defineClassUnder("KDFError", OpenSSLError, OpenSSLError.getAllocator());
        KDF.defineAnnotatedMethods(KDF.class);
    }

    private static final String[] PBKDF2_ARGS = new String[] { "salt", "iterations", "length", "hash" };
    private static final String[] HKDF_ARGS = new String[] { "salt", "info", "length", "hash" };

    @JRubyMethod(module = true) // pbkdf2_hmac(pass, salt:, iterations:, length:, hash:)
    public static IRubyObject pbkdf2_hmac(ThreadContext context, IRubyObject self, IRubyObject pass, IRubyObject opts) {
        IRubyObject[] args = extractKeywordArgs(context, (RubyHash) opts, PBKDF2_ARGS, 1);
        args[0] = pass;
        try {
            return PKCS5.pbkdf2Hmac(context.runtime, args);
        }
        catch (NoSuchAlgorithmException|InvalidKeyException e) {
            throw newKDFError(context.runtime, e.getMessage());
        }
    }

    @JRubyMethod(module = true) // hkdf(ikm, salt:, info:, length:, hash:)
    public static IRubyObject hkdf(ThreadContext context, IRubyObject self, IRubyObject ikm, IRubyObject opts) {
        IRubyObject[] args = extractKeywordArgs(context, (RubyHash) opts, HKDF_ARGS, 0);
        try {
            return hkdfImpl(context.runtime, ikm, args);
        }
        catch (NoSuchAlgorithmException|InvalidKeyException e) {
            throw newKDFError(context.runtime, e.getMessage());
        }
    }

    static RubyString hkdfImpl(final Ruby runtime, final IRubyObject ikmArg, final IRubyObject[] args)
        throws NoSuchAlgorithmException, InvalidKeyException {
        final byte[] ikm = ikmArg.convertToString().getBytes();
        final byte[] salt = args[0].convertToString().getBytes();
        final byte[] info = args[1].convertToString().getBytes();

        final long length = RubyNumeric.num2long(args[2]);
        if (length < 0) throw runtime.newArgumentError("length must be non-negative");

        if (SecurityHelper.isRequiredProviderMode()) {
            return StringHelper.newString(runtime,
                    FipsHKDF.derive(runtime, ikm, salt, info, length, args[3]));
        }

        final Mac mac = getMac(args[3]);
        final int macLength = mac.getMacLength();
        if (length > 255L * macLength) {
            throw newKDFError(runtime, "length must be <= 255 * HashLen");
        }

        mac.init(new SimpleSecretKey(mac.getAlgorithm(), salt));
        final byte[] prk = mac.doFinal(ikm);

        mac.init(new SimpleSecretKey(mac.getAlgorithm(), prk));

        final byte[] okm = new byte[(int) length];
        byte[] block = new byte[0];
        int offset = 0;

        for (int i = 1; offset < okm.length; i++) {
            if (block.length > 0) mac.update(block);
            if (info.length > 0) mac.update(info);
            mac.update((byte) i);

            block = mac.doFinal();

            final int copyLength = Math.min(block.length, okm.length - offset);
            System.arraycopy(block, 0, okm, offset, copyLength);
            offset += copyLength;
        }

        return StringHelper.newString(runtime, okm);
    }

    /**
     * Reflective isolation is intentional: FipsKDF is a bc-fips module API,
     * not a JCA service, and is absent from the normal non-FIPS BC classpath.
     */
    private static final class FipsHKDF {
        private static byte[] derive(final Ruby runtime, final byte[] ikm,
                final byte[] salt, final byte[] info, final long length,
                final IRubyObject digest) {
            final String digestName = HMAC.getDigestAlgorithmName(digest)
                    .toUpperCase(Locale.ENGLISH).replace("-", "").replace("_", "");
            final String prfName;
            final int hashLength;
            switch (digestName) {
                case "SHA1": prfName = "SHA1_HMAC"; hashLength = 20; break;
                case "SHA224": prfName = "SHA224_HMAC"; hashLength = 28; break;
                case "SHA256": prfName = "SHA256_HMAC"; hashLength = 32; break;
                case "SHA384": prfName = "SHA384_HMAC"; hashLength = 48; break;
                case "SHA512": prfName = "SHA512_HMAC"; hashLength = 64; break;
                case "SHA512224": prfName = "SHA512_224_HMAC"; hashLength = 28; break;
                case "SHA512256": prfName = "SHA512_256_HMAC"; hashLength = 32; break;
                case "SHA3224": prfName = "SHA3_224_HMAC"; hashLength = 28; break;
                case "SHA3256": prfName = "SHA3_256_HMAC"; hashLength = 32; break;
                case "SHA3384": prfName = "SHA3_384_HMAC"; hashLength = 48; break;
                case "SHA3512": prfName = "SHA3_512_HMAC"; hashLength = 64; break;
                default:
                    throw newKDFError(runtime,
                            "unsupported hash for FipsKDF HKDF: " + digestName);
            }
            if (length > 255L * hashLength) {
                throw newKDFError(runtime, "length must be <= 255 * HashLen");
            }
            if (length > Integer.MAX_VALUE) {
                throw runtime.newArgumentError("length is too large");
            }

            try {
                final ClassLoader loader =
                        SecurityHelper.getSecurityProvider().getClass().getClassLoader();
                final Class<?> fipsKdf = Class.forName(
                        "org.bouncycastle.crypto.fips.FipsKDF", true, loader);
                final Class<?> prfClass = Class.forName(
                        "org.bouncycastle.crypto.fips.FipsKDF$AgreementKDFPRF", true, loader);
                @SuppressWarnings({ "rawtypes", "unchecked" })
                final Object prf = Enum.valueOf((Class<? extends Enum>) prfClass, prfName);

                Object keyBuilder = fipsKdf.getField("HKDF_KEY_BUILDER").get(null);
                keyBuilder = keyBuilder.getClass()
                        .getMethod("withPrf", prfClass).invoke(keyBuilder, prf);
                keyBuilder = keyBuilder.getClass()
                        .getMethod("withSalt", byte[].class).invoke(keyBuilder, (Object) salt);
                final Object hkdfKey = keyBuilder.getClass()
                        .getMethod("build", byte[].class).invoke(keyBuilder, (Object) ikm);
                final byte[] prk = (byte[]) hkdfKey.getClass().getMethod("getKey").invoke(hkdfKey);

                Object parametersBuilder = fipsKdf.getField("HKDF").get(null);
                parametersBuilder = parametersBuilder.getClass()
                        .getMethod("withPRF", prfClass).invoke(parametersBuilder, prf);
                Object parameters = parametersBuilder.getClass()
                        .getMethod("using", byte[].class).invoke(parametersBuilder, (Object) prk);
                parameters = parameters.getClass()
                        .getMethod("withIV", byte[].class).invoke(parameters, (Object) info);

                final Class<?> parametersClass = Class.forName(
                        "org.bouncycastle.crypto.fips.FipsKDF$AgreementKDFParameters",
                        true, loader);
                final Class<?> factoryClass = Class.forName(
                        "org.bouncycastle.crypto.fips.FipsKDF$AgreementOperatorFactory",
                        true, loader);
                final Object factory = factoryClass.getConstructor().newInstance();
                final Object calculator = factoryClass
                        .getMethod("createKDFCalculator", parametersClass)
                        .invoke(factory, parameters);
                final byte[] okm = new byte[(int) length];
                final Class<?> calculatorClass = Class.forName(
                        "org.bouncycastle.crypto.KDFCalculator", true, loader);
                calculatorClass.getMethod(
                        "generateBytes", byte[].class, int.class, int.class)
                        .invoke(calculator, okm, 0, okm.length);
                return okm;
            }
            catch (Exception e) {
                final Throwable target = e instanceof InvocationTargetException ?
                        ((InvocationTargetException) e).getTargetException() : e;
                final Exception cause = target instanceof Exception ?
                        (Exception) target : e;
                throw newKDFError(runtime,
                        "FipsKDF HKDF failed: " + cause.getMessage(), cause);
            }
        }
    }

    private static Mac getMac(final IRubyObject digest) throws NoSuchAlgorithmException {
        final String digestAlg = HMAC.getDigestAlgorithmName(digest);
        return HMAC.getMacInstance(digestAlg);
    }

    static RaiseException newKDFError(Ruby runtime, String message) {
        return Utils.newError(runtime, _KDF(runtime).getClass("KDFError"), message);
    }

    static RaiseException newKDFError(Ruby runtime, String message, Exception cause) {
        return Utils.newError(runtime, _KDF(runtime).getClass("KDFError"), message, cause);
    }

    static RubyClass _KDF(final Ruby runtime) {
        return (RubyClass) runtime.getModule("OpenSSL").getConstant("KDF");
    }

}
