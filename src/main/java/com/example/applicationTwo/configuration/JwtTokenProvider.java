package com.example.applicationTwo.configuration;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private PublicKey jwtSecret;

    public JwtTokenProvider(@Value("${jwt.public-key}") String publicKeyString){
        this.jwtSecret = convertStringToPublicKey(publicKeyString);
    }

    // Convert Base64-encoded String to PublicKey
    private PublicKey convertStringToPublicKey(String publicKeyString) {
        try {
            // Remove any unwanted characters (optional, but useful for formatting issues)
//            publicKeyString = publicKeyString.replaceAll("\\n", "").replaceAll("\\r", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

            // Decode Base64 string into bytes
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);

            // Generate PublicKey from bytes
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");  // Use "EC" for Elliptic Curve keys
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Error while converting string to PublicKey", e);
        }
    }




    // 🔹 Validate JWT Token using the Public Key
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(jwtSecret)
                    .build()
                    .parseSignedClaims(token);

            return true;  // Token is valid

            // Valid if expiry is not reached
        } catch (ExpiredJwtException ex){
            System.out.println("JWT Token has expired: " + ex.getMessage());
            return false;  // Handle expired token
        } catch (MalformedJwtException ex){
            System.out.println("Malformed JWT token: " + ex.getMessage());
            return false;
        } catch (UnsupportedJwtException ex){
            System.out.println("Unsupported JWT token: " + ex.getMessage());
            return false;
        } catch ( IllegalArgumentException ex) {
            System.out.println("JWT claims string is empty or null: " + ex.getMessage());
            return false;
        }

    }

   //Get the username (subject) from the JWT token
    public String getUsernameFromToken(String token) {
        Jws<Claims> jwsClaims = Jwts.parser()
                .verifyWith(jwtSecret) // Set the signing key to verify the token
                .build()
                .parseSignedClaims(token);  // Parse the token claims

        return jwsClaims.getPayload().get("preferred_username", String.class);  // Return the username (subject) from the claims
    }

    public Claims getClaims(String token){
        Jws<Claims> jwsClaims = Jwts.parser()
                .verifyWith(jwtSecret) // Set the signing key to verify the token
                .build()
                .parseSignedClaims(token);  // Parse the token claims

        return jwsClaims.getPayload();
    }

}
