package asset.spy.auth.lib.exception;

public class UnauthorizedException extends AuthLibException{
    public UnauthorizedException(String message) {
        super(message);
    }
    public UnauthorizedException(String message, Throwable cause) {
        super(message, cause);
    }
}
