package asset.spy.auth.lib.exception;

public class AuthLibException extends RuntimeException {
    public AuthLibException(String message) {
        super(message);
    }
    public AuthLibException(String message, Throwable cause) {
        super(message, cause);
    }
}
