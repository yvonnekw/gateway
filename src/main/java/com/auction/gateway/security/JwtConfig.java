package com.auction.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

@Configuration
public class JwtConfig {

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        String jwkSetUri = "http://localhost:9098/realms/auction-realm/protocol/openid-connect/certs"; // Example for Keycloak
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }
}