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

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }


    public String extractRole(String token) {
        return extractClaims(token).get("role", String.class);
    }

    public UUID extractExternalId(String token) {
        Claims claims = extractClaims(token);
        String externalId = claims.get("externalId", String.class);
        return UUID.fromString(externalId);
    }

    public Claims extractClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Expired JWT token", e);
        } catch (Exception e) {
            throw new InvalidJwtException("Invalid JWT token", e);
        }
    }

    public boolean validateTokenOrThrow(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Expired or invalid JWT token", e);
        } catch (UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            throw new InvalidJwtException("Invalid JWT token", e);
        } catch (Exception e) {
            throw new InvalidJwtException("Unexpected error while validating JWT token", e);
        }
    }
}
