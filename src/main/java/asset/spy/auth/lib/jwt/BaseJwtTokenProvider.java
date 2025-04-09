package asset.spy.auth.lib.jwt;

import asset.spy.auth.lib.exception.InvalidJwtException;
import asset.spy.auth.lib.exception.TokenExpiredException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.UUID;

@Component
public class BaseJwtTokenProvider {
    @Value("${security.jwt.secret}")
    private String secret;

    public String extractRole(String token) {
        return extractClaims(token).get("role", String.class);
    }

    public UUID extractExternalId(String token) {
        Claims claims = extractClaims(token);
        return UUID.fromString(claims.get("externalId", String.class));
    }

    public String extractLogin(String token) {
        return extractClaims(token).getSubject();
    }

    public void validateTokenOrThrow(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Expired or invalid JWT token", e);
        } catch (UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            throw new InvalidJwtException("Invalid JWT token", e);
        } catch (Exception e) {
            throw new InvalidJwtException("Unexpected error while validating JWT token", e);
        }
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }
}
