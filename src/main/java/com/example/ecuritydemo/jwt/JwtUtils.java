package com.example.ecuritydemo.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    //Getting JWT from header
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization header: {}", bearerToken);

        if(bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }

    //Generating token from Username
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    //Getting Username from JWT token
    public String getUsernameFromJwtToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    //Generate signing key
    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecret)
        );
    }

    // Validate JWT token
    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(token);

            return true;
        } catch (SignatureException e) {

            logger.error("Invalid JWT signature: {}",
                    e.getMessage());

        } catch (MalformedJwtException e) {

            logger.error("Invalid JWT token: {}",
                    e.getMessage());

        } catch (ExpiredJwtException e) {

            logger.error("JWT token is expired: {}",
                    e.getMessage());

        } catch (UnsupportedJwtException e) {

            logger.error("JWT token is unsupported: {}",
                    e.getMessage());

        } catch (IllegalArgumentException e) {

            logger.error("JWT claims string is empty: {}",
                    e.getMessage());

        }

        return false;
    }
}
