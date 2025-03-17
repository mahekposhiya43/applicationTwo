package com.example.applicationTwo.configuration;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component
public class JwtTokenProvider {

    private final JwtDecoder jwtDecoder;

    public JwtTokenProvider() {
        this.jwtDecoder = JwtDecoders.fromIssuerLocation("http://127.0.0.1:8080/realms/admin_realm");
    }

    public boolean validateToken(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(
                jwt.getClaimAsString("roles"));
        return new UsernamePasswordAuthenticationToken(jwt.getSubject(), token, authorities);
    }
}
