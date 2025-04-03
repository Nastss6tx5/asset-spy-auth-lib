package asset.spy.auth.lib.exception;

public class InvalidJwtException extends AuthLibException{
    public InvalidJwtException(String message) {
        super(message);
    }
    public InvalidJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
