package com.central.auth.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtils {
    // Move this token to .env in production
    private static final String JWT_SECRET = "6ABLyuqr7oIb15+z78ey5M10AFDGC2rgNZLVKe8fj+CtspGR38QItxQkpUGyitjxybnsXhUUOXb4SclCzQ4/Hn0PkCNTkuloDVNPMrVRmuNmO+5ELgZuFYtL1HaGDu0tJjNrJlgzfy3RpqqI5AW4bc4gQ4RjIez+JFnjS7N79Jvn";
    private static final long EXPIRATION_TIME = 864_000_000; // 10 days
    private final SecretKey key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));

    public String createJwtToken(String login) {
        return Jwts.builder()
                .subject(login)
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS512)
                .compact();
    }

    public void setJwtCookie(HttpServletResponse response, String jwtToken) {
        Cookie jwtCookie = new Cookie("JWT_TOKEN", jwtToken);
        jwtCookie.setSecure(true);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setMaxAge((int) EXPIRATION_TIME / 1000);
        jwtCookie.setPath("/");
        response.addCookie(jwtCookie);
    }

    public boolean validateToken(@NonNull String token) {
        try {
            var claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
