package org.jruby.ext.openssl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.exceptions.RaiseException;
import org.junit.jupiter.api.Test;

public class UtilsTest {

    @Test
    void nullExceptionMessageUsesClassNameInRubyError() {
        final Ruby runtime = Ruby.newInstance();
        try {
            OpenSSL.createOpenSSL(runtime);
            final RubyClass cipherError = Cipher._Cipher(runtime).getClass("CipherError");
            final Exception ex = new NullMessageException();

            final RaiseException error = Utils.newError(runtime, cipherError, ex);
            final String message = error.getException().getMessage().toString();

            assertEquals(ex.getClass().getName(), message);
            assertFalse(message.isEmpty());
        }
        finally {
            runtime.tearDown(false);
        }
    }

    private static final class NullMessageException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        NullMessageException() {
            super((String) null);
        }
    }
}
