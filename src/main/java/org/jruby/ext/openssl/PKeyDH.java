/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2007 William N Dortch <bill.dortch@gmail.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the EPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the EPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.jruby.Ruby;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.jruby.runtime.Visibility;

import static org.jruby.ext.openssl.OpenSSL.bcExceptionMessage;

/**
 * OpenSSL::PKey::DH implementation.
 *
 * @author <a href="mailto:bill.dortch@gmail.com">Bill Dortch</a>
 */
public class PKeyDH extends PKey {

    private static final long serialVersionUID = -1893518804744046740L;

    private static final BigInteger TWO = BN.TWO;

    // from [ossl]/crypto/dh/dh.h
    private static final int OPENSSL_DH_MAX_MODULUS_BITS = 10000;

    private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public PKeyDH allocate(Ruby runtime, RubyClass klass) { return new PKeyDH(runtime, klass); }
    };

    static void createPKeyDH(final Ruby runtime, final RubyModule PKey, final RubyClass PKeyPKey, final RubyClass PKeyError) {
        RubyClass DH = PKey.defineClassUnder("DH", PKeyPKey, ALLOCATOR);
        PKey.defineClassUnder("DHError", PKeyError, PKeyError.getAllocator());
        DH.defineAnnotatedMethods(PKeyDH.class);
    }

    public static RaiseException newDHError(Ruby runtime, String message) {
        return Utils.newError(runtime, _PKey(runtime).getClass("DHError"), message);
    }

    public static RaiseException newDHError(Ruby runtime, String message, Exception cause) {
        return Utils.newError(runtime, _PKey(runtime).getClass("DHError"), message, cause);
    }

    // transient because: we do not want these value serialized (insecure)
    // volatile because: permits unsynchronized reads in some cases
    private transient volatile BigInteger dh_p;
    private transient volatile BigInteger dh_g;
    private transient volatile BigInteger dh_y;
    private transient volatile BigInteger dh_x;

    public PKeyDH(Ruby runtime, RubyClass clazz) {
        super(runtime, clazz);
    }

    @Override
    @JRubyMethod
    public RubyString oid() {
        return getRuntime().newString("dhKeyAgreement");
    }

    @Override
    @JRubyMethod
    public RubyString to_text() {
        StringBuilder result = new StringBuilder();
        if (dh_p != null) {
            result.append("DH Parameters: (").append(dh_p.bitLength()).append(" bit)").append('\n');
            result.append("    prime:");
            addSplittedAndFormatted(result, dh_p);
            result.append("    generator: ").append(dh_g).append(" (0x").append(dh_g.toString(16)).append(")\n");
        }
        if (dh_x != null) {
            result.append("    private-key:");
            addSplittedAndFormatted(result, dh_x);
        }
        if (dh_y != null) {
            result.append("    public-key:");
            addSplittedAndFormatted(result, dh_y);
        }
        return RubyString.newString(getRuntime(), result.toString());
    }

    @JRubyMethod(visibility = Visibility.PRIVATE)
    @Override
    public IRubyObject initialize_copy(final IRubyObject original) {
        if (this == original) return this;
        checkFrozen();

        final PKeyDH that = (PKeyDH) original;
        this.dh_p = that.dh_p;
        this.dh_g = that.dh_g;
        this.dh_y = that.dh_y;
        this.dh_x = that.dh_x;
        return this;
    }

    @JRubyMethod(name = "generate", meta = true, rest = true)
    public static IRubyObject generate(final ThreadContext context, IRubyObject self, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        final int g;
        if (Arity.checkArgumentCount(runtime, args, 1, 2) == 2) {
            g = RubyNumeric.num2int(args[1]);
        } else {
            g = 2;
        }

        PKeyDH pkey = new PKeyDH(runtime, _PKey(runtime).getClass("DH"));
        pkey.generate(runtime, args[0], g);
        return pkey;
    }

    @JRubyMethod(name="initialize", rest=true, visibility = Visibility.PRIVATE)
    public synchronized IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;

        if (this.dh_p != null || this.dh_g != null || this.dh_y != null || this.dh_x != null) {
            throw newDHError(runtime, "illegal initialization");
        }

        final int argc = Arity.checkArgumentCount(runtime, args, 0, 2);
        if ( argc > 0 ) {
            IRubyObject arg0 = args[0];
            if ( argc == 1 && arg0 instanceof RubyString ) {
                try {
                    DHParameterSpec spec = PEMInputOutput.readDHParameters(new StringReader(arg0.toString()));
                    if (spec == null) {
                        spec = org.jruby.ext.openssl.impl.PKey.readDHParameter(arg0.asString().getByteList().bytes());
                    }
                    if (spec == null) {
                        throw runtime.newArgumentError("invalid DH PARAMETERS");
                    }
                    this.dh_p = spec.getP();
                    this.dh_g = spec.getG();
                }
                catch (NoClassDefFoundError e) {
                    throw newDHError(runtime, bcExceptionMessage(e));
                }
                catch (IOException e) {
                    throw runtime.newIOErrorFromException(e);
                }
            } else {
                generate(runtime, arg0, argc == 2 ? RubyNumeric.num2int(args[1]) : 2); // g defaults to 2
            }
        }
        return this;
    }

    private void generate(final Ruby runtime, final IRubyObject bits, final int gval) {
        if (SecurityHelper.isRequiredProviderMode()) {
            generateWithProvider(runtime, RubyNumeric.num2int(bits), gval);
            return;
        }

        BigInteger p;
        try {
            p = generateP(RubyNumeric.num2int(bits), gval);
        }
        catch(IllegalArgumentException e) {
            throw runtime.newArgumentError(e.getMessage());
        }
        BigInteger g = BigInteger.valueOf(gval);
        BigInteger x = generateX(p);
        BigInteger y = generateY(p, g, x);
        this.dh_p = p;
        this.dh_g = g;
        this.dh_x = x; // private key
        this.dh_y = y; // public key
    }

    private void generateWithProvider(final Ruby runtime, final int bits, final int requestedG) {
        if (bits < 2) throw runtime.newArgumentError("invalid bit length");
        if (requestedG < 2) throw runtime.newArgumentError("invalid generator");

        try {
            final KeyPairGenerator generator = SecurityHelper.getKeyPairGenerator("DH");
            generator.initialize(namedGroupForSize(bits), SecurityHelper.getSecureRandom());
            final KeyPair pair = generator.generateKeyPair();
            populateFromKeyPair(pair);
            if (!dh_g.equals(BigInteger.valueOf(requestedG))) {
                throw runtime.newArgumentError(
                        "configured provider selected generator " + dh_g +
                        "; requested generator " + requestedG + " was not honored");
            }
        }
        catch (RaiseException e) {
            throw e;
        }
        catch (Exception e) {
            throw newDHError(runtime, "can't generate DH key: " + e.getMessage(), e);
        }
    }

    /**
     * Selects the provider's approved FFDHE group by size. Java 11 exposes
     * NamedParameterSpec directly; the reflective bc-fips index keeps the same
     * provider-owned selection available on Java 8.
     */
    private static AlgorithmParameterSpec namedGroupForSize(final int bits) throws Exception {
        final String name = "ffdhe" + bits;
        try {
            final Class<?> namedSpec = Class.forName("java.security.spec.NamedParameterSpec");
            final Constructor<?> constructor = namedSpec.getConstructor(String.class);
            return (AlgorithmParameterSpec) constructor.newInstance(name);
        }
        catch (ClassNotFoundException e) {
            return bcFipsNamedGroup(name);
        }
    }

    private static DHParameterSpec bcFipsNamedGroup(final String name) throws Exception {
        final ClassLoader loader = SecurityHelper.getSecurityProvider().getClass().getClassLoader();
        final Class<?> idClass = Class.forName(
                "org.bouncycastle.crypto.asymmetric.DHDomainParametersID", true, loader);
        final Object id = Proxy.newProxyInstance(loader, new Class<?>[] { idClass },
                (proxy, method, args) -> {
                    if ("getName".equals(method.getName())) return name;
                    if ("toString".equals(method.getName())) return name;
                    if ("hashCode".equals(method.getName())) return name.hashCode();
                    if ("equals".equals(method.getName())) return proxy == args[0];
                    return null;
                });
        final Class<?> indexClass = Class.forName(
                "org.bouncycastle.crypto.asymmetric.DHDomainParametersIndex", true, loader);
        final Object parameters = indexClass
                .getMethod("lookupDomainParameters", idClass).invoke(null, id);
        if (parameters == null) {
            throw new GeneralSecurityException(
                    "configured provider has no approved named DH group " + name);
        }
        final BigInteger p = (BigInteger) parameters.getClass().getMethod("getP").invoke(parameters);
        final BigInteger g = (BigInteger) parameters.getClass().getMethod("getG").invoke(parameters);
        return new DHParameterSpec(p, g);
    }

    private void populateFromKeyPair(final KeyPair pair) throws GeneralSecurityException {
        if (!(pair.getPublic() instanceof DHPublicKey) ||
                !(pair.getPrivate() instanceof DHPrivateKey)) {
            throw new GeneralSecurityException(
                    "configured provider returned non-DH key material");
        }
        final DHPublicKey publicKey = (DHPublicKey) pair.getPublic();
        final DHPrivateKey privateKey = (DHPrivateKey) pair.getPrivate();
        final DHParameterSpec parameters = publicKey.getParams();
        this.dh_p = parameters.getP();
        this.dh_g = parameters.getG();
        this.dh_y = publicKey.getY();
        this.dh_x = privateKey.getX();
    }

    public static BigInteger generateP(int bits, int g) {

        // FIXME? I'm following algorithms used in OpenSSL, could use JCE provider instead.
        // (Note that I tried that, but got mystifying values of g returned by the param generator.
        // In any case, in OpenSSL/MRI-OpenSSL, the caller supplies g, or it defaults to 2.)

        // see [ossl]/crypto/dh/dh_gen.c #dh_builtin_genparams

        if (bits < 2) throw new IllegalArgumentException("invalid bit length");
        if (g < 2) throw new IllegalArgumentException("invalid generator");

        // generate safe prime meeting appropriate add/rem (mod) criteria

        switch (g) {
        // parameters used in generating 'p'; see [ossl]/crypto/dh/dh_gen.c #dh_builtin_genparams
        case 2 : // add = 24, rem = 11
            return BN.generatePrime(bits, true, BigInteger.valueOf(24), BigInteger.valueOf(11));
        case 5 : // add = 10, rem = 3
            return BN.generatePrime(bits, true, BigInteger.valueOf(10), BigInteger.valueOf(3));
        default: // add = 2, rem = 1
            return BN.generatePrime(bits, true, TWO, BigInteger.ONE);
        }
    }

    public static BigInteger generateX(BigInteger p, int limit) {
        if (limit < 0) throw new IllegalArgumentException("invalid limit");

        BigInteger x;
        SecureRandom secureRandom = SecurityHelper.isRequiredProviderMode() ?
                SecurityHelper.getSecureRandom() : new SecureRandom();
        // adapting algorithm from org.bouncycastle.crypto.generators.DHKeyGeneratorHelper,
        // see also [ossl]/crypto/dh/dh_key.c #generate_key
        if (limit == 0) {
            final BigInteger pSub2 = p.subtract(TWO);
            do {
                x = BN.randomIntegerInRange(pSub2, secureRandom);
            } while (x.equals(BigInteger.ZERO));
        } else {
            do {
                x = new BigInteger(limit, secureRandom);
            } while (x.equals(BigInteger.ZERO));
        }
        return x;
    }

    public static BigInteger generateX(BigInteger p) {
        // OpenSSL default l(imit) is p bits - 1 -- see [ossl]/crypto/dh/dh_key.c #generate_key
        return generateX(p, p.bitLength() - 1);
    }

    public static BigInteger generateY(BigInteger p, BigInteger g, BigInteger x) {
        return g.modPow(x, p);
    }

    @JRubyMethod(name = "generate_key!")
    public synchronized IRubyObject generate_key() {
        BigInteger p, g, x, y;
        if ((p = this.dh_p) == null || (g = this.dh_g) == null) {
            throw newDHError(getRuntime(), "can't generate key");
        }
        if (SecurityHelper.isRequiredProviderMode()) {
            try {
                final KeyPairGenerator generator = SecurityHelper.getKeyPairGenerator("DH");
                generator.initialize(new DHParameterSpec(p, g), SecurityHelper.getSecureRandom());
                populateFromKeyPair(generator.generateKeyPair());
                return this;
            }
            catch (Exception e) {
                throw newDHError(getRuntime(), "can't generate key: " + e.getMessage(), e);
            }
        }
        if ((x = this.dh_x) == null) {
            x = generateX(p);
        }
        y = generateY(p, g, x);
        this.dh_x = x;
        this.dh_y = y;
        return this;
    }

    @JRubyMethod(name = "compute_key")
    public synchronized IRubyObject compute_key(IRubyObject other_pub_key) {
        BigInteger x, y, p;
        if ((y = BN.asBigInteger(other_pub_key)) == null) {
            throw getRuntime().newArgumentError("invalid public key");
        }
        if ((x = this.dh_x) == null || (p = this.dh_p) == null) {
            throw newDHError(getRuntime(), "incomplete DH");
        }
        int plen;
        if ((plen = p.bitLength()) == 0 || plen > OPENSSL_DH_MAX_MODULUS_BITS) {
            throw newDHError(getRuntime(), "can't compute key");
        }
        final byte[] secret;
        if (SecurityHelper.isRequiredProviderMode()) {
            secret = computeKeyWithProvider(y);
        }
        else {
            secret = computeKey(y, x, p);
        }
        return getRuntime().newString(new ByteList(secret, false));
    }

    public static byte[] computeKey(BigInteger y, BigInteger x, BigInteger p) {
        return BN.toUnsignedBytes(y.modPow(x, p));
    }

    private byte[] computeKeyWithProvider(final BigInteger peerY) {
        try {
            final KeyAgreement agreement = SecurityHelper.getKeyAgreement("DH");
            agreement.init(getPrivateKey());
            agreement.doPhase(getKeyFactory().generatePublic(
                    new DHPublicKeySpec(peerY, dh_p, dh_g)), true);
            return stripLeadingZeroes(agreement.generateSecret());
        }
        catch (Exception e) {
            throw newDHError(getRuntime(), "can't compute key: " + e.getMessage(), e);
        }
    }

    private static byte[] stripLeadingZeroes(final byte[] secret) {
        int offset = 0;
        while (offset < secret.length - 1 && secret[offset] == 0) offset++;
        if (offset == 0) return secret;
        final byte[] stripped = new byte[secret.length - offset];
        System.arraycopy(secret, offset, stripped, 0, stripped.length);
        return stripped;
    }

    /**
     * Derives a shared secret from this DH key and the peer's DH public key.
     * Equivalent to CRuby's EVP_PKEY_derive for DH keys.
     */
    @Override
    @JRubyMethod(name = "derive")
    public IRubyObject derive(ThreadContext context, IRubyObject peer) {
        if (!(peer instanceof PKeyDH)) {
            throw newPKeyError(context.runtime, "EVP_PKEY_derive_set_peer");
        }
        final PKeyDH peerDH = (PKeyDH) peer;
        final BigInteger x = this.dh_x;
        final BigInteger p = this.dh_p;
        if (x == null || p == null) {
            throw newPKeyError(context.runtime, "EVP_PKEY_derive_init");
        }
        final BigInteger peerY = peerDH.dh_y;
        if (peerY == null) {
            throw newPKeyError(context.runtime, "EVP_PKEY_derive_set_peer");
        }
        final byte[] secret = SecurityHelper.isRequiredProviderMode() ?
                computeKeyWithProvider(peerY) : computeKey(peerY, x, p);
        return context.runtime.newString(new ByteList(secret, false));
    }

    @JRubyMethod(name = "public?")
    public RubyBoolean public_p() {
        return getRuntime().newBoolean(dh_y != null);
    }

    @Override
    public boolean isPrivateKey() {
        return dh_x != null;
    }

    @JRubyMethod(name = "private?")
    public RubyBoolean private_p() {
        return getRuntime().newBoolean(isPrivateKey());
    }

    @Override
    @JRubyMethod(name = { "to_pem", "to_s" }, alias = "export", rest = true)
    public RubyString to_pem(ThreadContext context, final IRubyObject[] args) {
        //Arity.checkArgumentCount(getRuntime(), args, 0, 2);

        //CipherSpec spec = null; char[] passwd = null;
        //if ( args.length > 0 ) {
        //    spec = cipherSpec( args[0] );
        //    if ( args.length > 1 ) passwd = password(args[1]);
        //}

        BigInteger p, g;
        synchronized(this) {
            p = this.dh_p;
            g = this.dh_g;
        }
        final StringWriter writer = new StringWriter();
        try {
            PEMInputOutput.writeDHParameters(writer, new DHParameterSpec(p, g));
        }
        catch (NoClassDefFoundError e) {
            throw newDHError(getRuntime(), bcExceptionMessage(e));
        }
        catch (IOException e) { // shouldn't happen (string/buffer io only)
            throw getRuntime().newIOErrorFromException(e);
        }
        return RubyString.newString(getRuntime(), writer.getBuffer());
    }

    @Override
    @JRubyMethod(name = "to_der")
    public RubyString to_der() {
        BigInteger p, g;
        synchronized (this) {
            p = this.dh_p;
            g = this.dh_g;
        }
        try {
            byte[] bytes = org.jruby.ext.openssl.impl.PKey.toDerDHKey(p, g);
            return StringHelper.newString(getRuntime(), bytes);
        } catch (NoClassDefFoundError e) {
            throw newDHError(getRuntime(), bcExceptionMessage(e));
        } catch (IOException ioe) {
            throw newDHError(getRuntime(), ioe.getMessage());
        }
    }

    @JRubyMethod(name = "params")
    public IRubyObject params() {
        BigInteger p, g, x, y;
        synchronized(this) {
            p = this.dh_p;
            g = this.dh_g;
            x = this.dh_x;
            y = this.dh_y;
        }
        final Ruby runtime = getRuntime();
        HashMap<IRubyObject, IRubyObject> params = new HashMap<IRubyObject, IRubyObject>();

        params.put(runtime.newString("p"), BN.newBN(runtime, p));
        params.put(runtime.newString("g"), BN.newBN(runtime, g));
        params.put(runtime.newString("pub_key"), BN.newBN(runtime, y));
        params.put(runtime.newString("priv_key"), BN.newBN(runtime, x));

        return RubyHash.newHash(runtime, params, runtime.getNil());
    }

    // don't need synchronized as value is volatile
    @JRubyMethod(name = "p")
    public IRubyObject get_p() {
        return newBN(dh_p);
    }

    @JRubyMethod(name = "p=")
    public synchronized IRubyObject set_p(IRubyObject arg) {
        this.dh_p = BN.asBigInteger(arg);
        return arg;
    }

    // don't need synchronized as value is volatile
    @JRubyMethod(name = "g")
    public IRubyObject get_g() {
        return newBN(dh_g);
    }

    @JRubyMethod(name = "g=")
    public synchronized IRubyObject set_g(IRubyObject arg) {
        this.dh_g = BN.asBigInteger(arg);
        return arg;
    }

    @JRubyMethod(name = "q")
    public IRubyObject q(final ThreadContext context) {
        return context.nil;
    }

    @JRubyMethod
    public IRubyObject set_pqg(final ThreadContext context, IRubyObject p, IRubyObject q, IRubyObject g) {
        set_p(p);
        if (!q.isNil()) {
            OpenSSL.warn(context, "JRuby-OpenSSL does not support setting q param on " + inspect());
        }
        set_g(g);
        return this;
    }

    // don't need synchronized as value is volatile
    @JRubyMethod(name = "pub_key")
    public IRubyObject pub_key() {
        return newBN(dh_y);
    }

    @Override
    public PublicKey getPublicKey() {
        try {
            return getKeyFactory().generatePublic(new DHPublicKeySpec(dh_y, dh_p, dh_g));
        }
        catch (InvalidKeySpecException ex) { throw new RuntimeException(ex); }
    }

    @JRubyMethod(name = "pub_key=")
    public synchronized IRubyObject set_pub_key(IRubyObject arg) {
        this.dh_y = BN.asBigInteger(arg);
        return arg;
    }

    // don't need synchronized as value is volatile
    @JRubyMethod(name = "priv_key")
    public IRubyObject priv_key() {
        return newBN(dh_x);
    }

    @Override
    public PrivateKey getPrivateKey() {
        try {
            return getKeyFactory().generatePrivate(new DHPrivateKeySpec(dh_x, dh_p, dh_g));
        }
        catch (InvalidKeySpecException ex) { throw new RuntimeException(ex); }
    }

    @JRubyMethod(name = "priv_key=")
    public synchronized IRubyObject set_priv_key(IRubyObject arg) {
        this.dh_x = BN.asBigInteger(arg);
        return arg;
    }

    @JRubyMethod
    public IRubyObject set_key(final ThreadContext context, IRubyObject pub_key, IRubyObject priv_key) {
        set_pub_key(pub_key);
        set_priv_key(priv_key);
        return this;
    }

    private IRubyObject newBN(BigInteger value) {
        if (value == null) return getRuntime().getNil();
        return BN.newBN(getRuntime(), value);
    }

    private static KeyFactory getKeyFactory() {
        try {
            return SecurityHelper.getKeyFactory("DiffieHellman");
        }
        catch (NoSuchAlgorithmException ex) { throw new RuntimeException(ex); }
    }

}
