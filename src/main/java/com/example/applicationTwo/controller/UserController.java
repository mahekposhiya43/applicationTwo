package com.example.applicationTwo.controller;

import com.example.applicationTwo.service.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class UserController {


    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = CookieUtils.getCookie(request, "REFRESH_TOKEN");

            if (refreshToken == null || refreshToken.isBlank()) {
                System.out.println("❌ Refresh Token is missing in cookies.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Missing Refresh Token"));
            }

            ResponseEntity<Map> tokenResponse = requestNewAccessToken(refreshToken);

            if (!tokenResponse.getStatusCode().is2xxSuccessful() || tokenResponse.getBody() == null) {
                System.out.println("⚠️ Invalid or expired refresh token.");

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid Refresh Token"));
            }

            Map<String, String> tokens = tokenResponse.getBody();
            String newAccessToken = tokens.get("access_token");

            if (newAccessToken == null || newAccessToken.isBlank()) {
                System.out.println("🚨 Token response does not contain an access token!");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Failed to refresh token"));
            }

            CookieUtils.addCookie(response, "access_token", newAccessToken, 3600);
            System.out.println("✅ Access token refreshed successfully.");

            return ResponseEntity.ok(tokens);
        } catch (Exception ex) {
            System.out.println("❌ Exception while refreshing token: " + ex.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal Server Error"));
        }
    }

    private ResponseEntity<Map> requestNewAccessToken(String refreshToken) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", "refresh_token");
        requestBody.add("client_id", "test_oidc");
        requestBody.add("refresh_token", refreshToken);
        requestBody.add("client_secret", "your_client_secret");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBody, headers);
        return restTemplate.exchange("http://127.0.0.1:8080/realms/admin_realm/protocol/openid-connect/token",
                HttpMethod.POST, request, new ParameterizedTypeReference<>() {});
    }
//    @GetMapping("/user")
//    public ResponseEntity<String> getUserData(@AuthenticationPrincipal Jwt jwt) {
//        return ResponseEntity.ok("Hello, " + jwt.getClaim("preferred_username"));
//    }
//
//    @PreAuthorize("hasRole('ADMIN')")
//    @GetMapping("/admin")
//    public ResponseEntity<String> getAdminData() {
//        return ResponseEntity.ok("Admin access granted!");
//    }
}
