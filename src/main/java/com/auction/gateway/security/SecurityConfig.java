package com.auction.gateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;


@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String[] PUBLIC_ENDPOINTS = {
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/swagger-resources/**",
            "/api-docs/**",
            "/aggregate/**",
            "/eureka/**",
            "/user-service/swagger-ui/**",
            "/api/v1/products/get-all-products",
            "/api/v1/products/{productId}",
            "/api/v1/products/search"
    };

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/products/{productId}/mark-as-bought").authenticated()
                        .pathMatchers(HttpMethod.PUT, "/api/v1/products/{productId}").authenticated()
                        .pathMatchers("/api/**").authenticated()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(token -> token.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())))
        ;

        return serverHttpSecurity.build();
    }
}


