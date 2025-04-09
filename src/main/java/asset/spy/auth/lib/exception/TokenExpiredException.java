package asset.spy.auth.lib.exception;

public class TokenExpiredException extends AuthLibException{
    public TokenExpiredException(String message) {
        super(message);
    }
    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
