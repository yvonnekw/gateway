package com.auction.gateway.security;


import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import java.util.Optional;

@Slf4j
@Component
public class JwtForwardingFilter implements WebFilter {

    private final JwtDecoder jwtDecoder;
    private final AdminTokenProvider adminTokenProvider;


    public JwtForwardingFilter(AdminTokenProvider adminTokenProvider) {
        this.adminTokenProvider = adminTokenProvider;
        String issuerUri = "http://localhost:9098/realms/auction-realm";
        this.jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
    }

    @Override
    public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        log.info("Incoming request: method={}, path={}, headers={}",
                exchange.getRequest().getMethod(), exchange.getRequest().getPath(), exchange.getRequest().getHeaders());

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("Incoming Authorization Header: {}", authHeader != null ? "[REDACTED]" : "Missing");

        String idempotencyKey = exchange.getRequest().getHeaders().getFirst("Idempotency-Key");

        String token = null;
        String username = "anonymous";
        String firstName = "unknown";
        String lastName = "unknown";
        String email = "unknown";

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            try {
                Jwt jwt = jwtDecoder.decode(token);
                log.debug("Decoded JWT claims: {}", jwt.getClaims());

                username = jwt.getClaimAsString("preferred_username");
                firstName = jwt.getClaimAsString("given_name");
                lastName = jwt.getClaimAsString("family_name");
                email = jwt.getClaimAsString("email");

            } catch (Exception e) {
                log.error("JWT decoding failed: {}", e.getMessage(), e);
            }
        } else {
            log.warn("Missing or invalid Authorization header.");
        }

        exchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .header("Authorization", token != null ? "Bearer " + token : "")
                        .header("X-Username", Optional.ofNullable(username).orElse(username))
                        .header("X-FirstName", Optional.ofNullable(firstName).orElse(firstName))
                        .header("X-LastName", Optional.ofNullable(lastName).orElse(lastName))
                        .header("X-Email", Optional.ofNullable(email).orElse(email))
                        .header("Idempotency-Key", Optional.ofNullable(idempotencyKey).orElse(""))
                        .build())
                .build();

        log.info("Forwarding request with updated headers.");
        return chain.filter(exchange);
    }
}
