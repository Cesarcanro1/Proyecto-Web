package com.example.proyecto.backend.security.jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    private final SecretKey key;
    private final long accessExpMinutes;
    private final Duration clockSkew = Duration.ofSeconds(60); // tolerancia 60s

    public JwtUtil(
            @Value("${security.jwt.secret}") String base64Secret,
            @Value("${security.jwt.access-exp-min:15}") long accessExpMinutes
    ) {
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(base64Secret));
        this.accessExpMinutes = accessExpMinutes;
    }

    public String generateAccessToken(UserDetails user, Map<String, Object> extraClaims) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(accessExpMinutes * 60);
        return Jwts.builder()
                .claims(extraClaims)
                .subject(user.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public boolean isValid(String token, UserDetails user) {
        try {
            Claims c = parseAllClaims(token);
            String username = c.getSubject();
            return username.equals(user.getUsername()) && c.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public List<String> extractRoles(String token) {
        Object roles = extractClaim(token, claims -> claims.get("roles"));
        if (roles instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(parseAllClaims(token));
    }

    public Claims parseAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .clockSkewSeconds(clockSkew.getSeconds())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
