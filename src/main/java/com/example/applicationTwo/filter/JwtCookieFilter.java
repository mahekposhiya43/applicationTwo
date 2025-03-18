package com.example.applicationTwo.filter;

import io.jsonwebtoken.*;
import com.example.applicationTwo.configuration.JwtTokenProvider;
import com.example.applicationTwo.service.CookieUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;


@Component
public class JwtCookieFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

public JwtCookieFilter (JwtTokenProvider jwtTokenProvider){
    this.jwtTokenProvider = jwtTokenProvider;
}

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String jwt  = extractTokenFromCookies(request);

        if(jwt != null && jwtTokenProvider.validateToken(jwt)){
            try {
                String username = jwtTokenProvider.getUsernameFromToken(jwt);

                Claims claims = jwtTokenProvider.getClaims(jwt);

                List<String> role = claims.get("groups", List.class);
                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.get(0).substring(1)));


                // Create the authentication object
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        username, null, authorities);  // You can load roles from DB if needed


                SecurityContextHolder.getContext().setAuthentication(authentication); // Set security context
                  SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException e){
                System.out.println("🔴 Token decoding failed: " + e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            }
        }else{

            String accessToken = extractTokenFromCookies(request);

            if (accessToken == null || !jwtTokenProvider.validateToken(accessToken)) {
                String refreshToken = extractRefreshTokenFromCookies(request);

                if (refreshToken != null) {
                    System.out.println("Generating new tokens");
                    String url = "http://localhost:8081/api/private/refresh-token";

                    RestTemplate restTemplate = new RestTemplate();

                    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();

                    HttpHeaders headers = new HttpHeaders();
                    headers.add(HttpHeaders.COOKIE, "REFRESH_TOKEN=" + refreshToken);

                    HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);
                    ResponseEntity<Map> resp = restTemplate.exchange(url, HttpMethod.POST, requestEntity, Map.class);

                    String newAccessToken = resp.getHeaders().get("Set-Cookie").get(0).split("=")[1].split("; ")[0];
                    String newRefreshToken = resp.getHeaders().get("Set-Cookie").get(1).split("=")[1].split("; ")[0];
                    String newIdToken = resp.getHeaders().get("Set-Cookie").get(2).split("=")[1].split("; ")[0];
//
//                        // Store new tokens in cookies
                    CookieUtils.addCookie(response, "ACCESS_TOKEN", newAccessToken, 60 * 15); // 15 min expiry
                    CookieUtils.addCookie(response, "REFRESH_TOKEN", newRefreshToken, 60 * 60 * 24 * 7); // 7 days expiry
                    CookieUtils.addCookie(response, "ID_TOKEN", newIdToken, 60 * 15);
                } else {
                    CookieUtils.deleteCookie(request, response, "JSESSIONID");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token is invalid or expired");
                    return;
                }
            }
        }


        filterChain.doFilter(request, response);
}

    private String extractTokenFromCookies(HttpServletRequest request) {
        if(request.getCookies() != null){
            Optional<Cookie> cookies = Arrays.stream(request.getCookies())
                    .filter(cookie -> "ACCESS_TOKEN".equals(cookie.getName()))
                    .findFirst();
            return cookies.map(Cookie::getValue).orElse(null);
        }
        return null;
    }


    private String extractRefreshTokenFromCookies(HttpServletRequest request) {
        if(request.getCookies() != null){
            Optional<Cookie> cookies = Arrays.stream(request.getCookies())
                    .filter(cookie -> "REFRESH_TOKEN".equals(cookie.getName()))
                    .findFirst();
            return cookies.map(Cookie::getValue).orElse(null);
        }
        return null;
    }

}
