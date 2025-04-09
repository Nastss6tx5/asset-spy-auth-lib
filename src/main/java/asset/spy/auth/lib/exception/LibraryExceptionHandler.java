package asset.spy.auth.lib.exception;

import asset.spy.auth.lib.dto.ErrorResponseDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
@Order(1)
public class LibraryExceptionHandler {

    @ExceptionHandler(InvalidJwtException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidJwtException(final InvalidJwtException e) {
        log.error("Invalid jwt exception: {}", e.getMessage(), e);
        ErrorResponseDto error = new ErrorResponseDto(e.getMessage(), "INVALID_JWT", HttpStatus.BAD_REQUEST.value());
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ErrorResponseDto> handleTokenExpiredException(final TokenExpiredException e) {
        log.error("Token expired exception: {}", e.getMessage(), e);
        ErrorResponseDto error = new ErrorResponseDto(e.getMessage(), "TOKEN_EXPIRED", HttpStatus.UNAUTHORIZED.value());
        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponseDto> handleAccessDeniedException(final AccessDeniedException e) {
        log.error("Access denied exception: {}", e.getMessage(), e);
        ErrorResponseDto error = new ErrorResponseDto(e.getMessage(), "ACCESS_DENIED", HttpStatus.FORBIDDEN.value());
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponseDto> handleAuthorizationException(final AuthenticationException e) {
        log.error("Authentication exception: {}", e.getMessage(), e);
        ErrorResponseDto error = new ErrorResponseDto(e.getMessage(), "AUTHENTICATION_FAILED", HttpStatus.UNAUTHORIZED.value());
        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }
}