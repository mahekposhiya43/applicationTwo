package com.example.applicationTwo.controller;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

@RequestMapping("/user")
public class UserController {

    @GetMapping("/profile")
    public Map<String, Object> getUserProfile(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "username", jwt.getSubject(),
                "roles", jwt.getClaimAsStringList("realm_access.roles") // Extract roles
        );
    }
}
