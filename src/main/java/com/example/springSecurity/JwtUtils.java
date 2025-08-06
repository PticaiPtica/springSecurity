package com.example.springSecurity;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtils {

    // Секретный ключ для подписи токена (лучше хранить в настройках)
    @Value("${jwt.secret}")
    private String secret;

    // Время жизни токена в миллисекундах (24 часа)
    @Value("${jwt.expiration}")
    private long expiration;

    // Генерация секретного ключа
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    // Генерация токена на основе UserDetails
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        // Добавляем роли в claims
        claims.put("roles", userDetails.getAuthorities());
        return Jwts.builder()
                .claims(claims) // Дополнительные данные
                .subject(userDetails.getUsername()) // Логин пользователя
                .issuedAt(new Date(System.currentTimeMillis())) // Время создания
                .expiration(new Date(System.currentTimeMillis() + expiration)) // Время истечения
                .signWith(getSigningKey()) // Подпись
                .compact(); // Генерация строки
    }

    // Извлечение username из токена
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Извлечение даты истечения
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Проверка валидности токена
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // Проверка истечения срока действия
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Общий метод извлечения данных из токена
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Извлечение всех claims из токена
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}

