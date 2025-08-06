package com.example.springSecurity.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;


import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;


public class JwtTokenProvider {

    @Value("${app.jwt.secret}")
    private String jwSecret;

    @Value("${app.jwt,expiration-ms")
    private long jwtExpirationMs;

    private SecretKey getSecretKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return Jwts.builder().subject(username)
                .claim("roles", roles)
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getSecretKey()).compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSecretKey()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            System.err.println("Invalid JWT : " + e.getMessage())
            ;
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload().getSubject();

    }


}
