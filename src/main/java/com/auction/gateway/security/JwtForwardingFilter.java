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

import java.util.List;
import java.util.Map;

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
        log.info("Incoming headers: {}", exchange.getRequest().getHeaders());

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("Incoming Authorization Header: {}", authHeader);

        String username = "anonymous";
        String firstName = "unknown";
        String lastName = "unknown";
        String email = "unknown";

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                Jwt jwt = jwtDecoder.decode(token);
                log.info("JWT Claims: {}", jwt.getClaims());

                username = jwt.getClaimAsString("preferred_username");
                firstName = jwt.getClaimAsString("given_name");
                lastName = jwt.getClaimAsString("family_name");
                email = jwt.getClaimAsString("email");

                log.info("Extracted user info: username={}, firstName={}, lastName={}, email={}",
                        username, firstName, lastName, email);
            } catch (Exception e) {
                log.error("Failed to decode JWT: {}", e.getMessage(), e);
            }
        }

        exchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .header("X-Username", username)
                        .header("X-FirstName", firstName)
                        .header("X-LastName", lastName)
                        .header("X-Email", email)
                        .build())
                .build();

        log.info("Final headers after mutation: {}", exchange.getRequest().getHeaders());

        return chain.filter(exchange);
    }
}
/*
    @Override
    public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        log.info("Incoming headers: {}", exchange.getRequest().getHeaders());

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("Incoming Authorization Header: {}", authHeader);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Extract the token part

            Jwt jwt = jwtDecoder.decode(token);

            // Extract user details
            String username = jwt.getClaimAsString("preferred_username");
            String firstName = jwt.getClaimAsString("given_name");
            String lastName = jwt.getClaimAsString("family_name");
            String email = jwt.getClaimAsString("email");

            log.info("Extracted username: {}, firstName: {}, lastName: {}, email: {}", username, firstName, lastName, email);

            // Extract the realm_access claim (which contains roles)
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");

            if (realmAccess != null && realmAccess.containsKey("roles")) {
                // Extract the roles list from the realm_access object
                List<String> roles = (List<String>) realmAccess.get("roles");
                log.info("Extracted realm access roles: {}", roles);

                // Check if the roles list contains "admin"
                if (roles != null && roles.contains("admin")) {
                    String userRole = roles.contains("admin") ? "admin" : "user";
                    log.info("Determined user role: {}", userRole);
                    log.info("The role 'admin' is present in the roles list.");

                    exchange = exchange.mutate()
                            .request(exchange.getRequest().mutate()
                                    .header("X-Username", username)
                                    .header("X-FirstName", firstName)
                                    .header("X-LastName", lastName)
                                    .header("X-Email", email)
                                    .header("X-User-Role", userRole)
                                    .build())
                            .build();
                    log.info("Forwarding headers: {}", exchange.getRequest().getHeaders());
                } else {
                    log.warn("The role 'user' is not present in the roles list.");
                }
            } else {
                log.warn("The 'realm_access' claim or 'roles' are missing in the JWT.");
            }

        }

        // Inject the admin token for internal API calls
        String adminToken = adminTokenProvider.getAdminToken();
        if (adminToken != null) {
            log.info("Injecting admin token into request headers.");
            exchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-Admin-Token", "Bearer " + adminToken) // Pass the admin token
                            .build())
                    .build();

        }

        return chain.filter(exchange);
    }
}
*/
    /*
    @Override
    public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        log.info("Incoming headers: {}", exchange.getRequest().getHeaders());

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("Incoming Authorization Header: {}", authHeader);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Extract the token part

            Jwt jwt = jwtDecoder.decode(token);

            // Extract user details
            String username = jwt.getClaimAsString("preferred_username");
            String firstName = jwt.getClaimAsString("given_name");
            String lastName = jwt.getClaimAsString("family_name");
            String email = jwt.getClaimAsString("email");

            log.info("Extracted username: {}, firstName: {}, lastName: {}, email: {}", username, firstName, lastName, email);

            // Extract roles from the token
            List<String> roles = jwt.getClaimAsStringList("realm_access");
            log.info("Extracted roles: {}", roles);

            String role = jwt.getClaimAsString("realm_access.roles");
            log.info("Extracted role: {}", role);

            // Determine user role and set appropriate headers
            String userRole = roles.contains("admin") ? "admin" : "user";
            log.info("Determined user role: {}", userRole);

            exchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-Username", username)
                            .header("X-FirstName", firstName)
                            .header("X-LastName", lastName)
                            .header("X-Email", email)
                            .header("X-User-Role", userRole)
                            .build())
                    .build();
        }

        // Inject the admin token for internal API calls
        String adminToken = adminTokenProvider.getAdminToken();
        if (adminToken != null) {
            log.info("Injecting admin token into request headers.");
            exchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-Admin-Token", "Bearer " + adminToken) // Pass the admin token
                            .build())
                    .build();
        }

        return chain.filter(exchange);
    }
}
*/
/*
    @Override
    public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            Jwt jwt = jwtDecoder.decode(token);

            List<String> roles = jwt.getClaimAsStringList("realm_access.roles");

            if (roles.contains("admin")) {
                log.info("Admin token detected.");
                exchange = exchange.mutate()
                        .request(exchange.getRequest().mutate()
                                .header("X-User-Role", "admin")
                                .build())
                        .build();
            } else if (roles.contains("user")) {
                log.info("User token detected.");
                exchange = exchange.mutate()
                        .request(exchange.getRequest().mutate()
                                .header("X-User-Role", "user")
                                .build())
                        .build();
            } else {
                log.warn("Unauthorized role.");
                return exchange.getResponse().setComplete(); // Reject request
            }
        }

        return chain.filter(exchange);
    }
}
 */
/*
    @Override
    public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        log.info("Incoming headers: {}", exchange.getRequest().getHeaders());

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("Incoming Authorization Header: {}", authHeader);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Extract the token part

            Jwt jwt = jwtDecoder.decode(token);

            String username = jwt.getClaimAsString("preferred_username");
            String firstName = jwt.getClaimAsString("given_name");
            String lastName = jwt.getClaimAsString("family_name");
            String email = jwt.getClaimAsString("email");

            log.info("Extracted username: {}, firstName: {}, lastName: {}, email: {}", username, firstName, lastName, email);

            exchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-Username", username)
                            .header("X-FirstName", firstName)
                            .header("X-LastName", lastName)
                            .header("X-Email", email)
                            .build())
                    .build();
        }

        // Inject the admin token for internal API calls
        String adminToken = adminTokenProvider.getAdminToken();
        if (adminToken != null) {
            log.info("Injecting admin token into request headers.");
            exchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-Admin-Token", "Bearer " + adminToken) // Pass the admin token
                            .build())
                    .build();
        }

        return chain.filter(exchange);
    }
}
*/
/*
@Slf4j
@Component
public class JwtForwardingFilter implements WebFilter {

    private final JwtDecoder jwtDecoder;

    public JwtForwardingFilter() {
        String issuerUri = "http://localhost:9098/realms/auction-realm";
        this.jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
    }

    @Override
    public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        log.info("Incoming headers: {}", exchange.getRequest().getHeaders());

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("Incoming Authorization Header: {}", authHeader);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Extract the token part

            // Decode the JWT token (validates and extracts claims)
            Jwt jwt = jwtDecoder.decode(token);

            // Extract the relevant claims from the JWT
            String username = jwt.getClaimAsString("preferred_username");
            String firstName = jwt.getClaimAsString("given_name"); // first name from JWT
            String lastName = jwt.getClaimAsString("family_name"); // last name from JWT
            String email = jwt.getClaimAsString("email"); // email from JWT

            log.info("Extracted username: {}, firstName: {}, lastName: {}, email: {}", username, firstName, lastName, email);

            // Optionally: You can log or check the claims
            System.out.println("Extracted username: " + username);
            System.out.println("Extracted firstName: " + firstName);
            System.out.println("Extracted lastName: " + lastName);
            System.out.println("Extracted email: " + email);

            // Mutate the request to add the username, firstName, lastName, and email as custom headers
            exchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-Username", username) // Add the username to request headers
                            .header("X-FirstName", firstName) // Add the firstName to request headers
                            .header("X-LastName", lastName) // Add the lastName to request headers
                            .header("X-Email", email) // Add the email to request headers
                            .build())
                    .build();
        }

        // Continue with the request chain, passing the mutated request with the added headers
        return chain.filter(exchange);
    }
*/

    /*
    @Override
    public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        log.info("Incoming headers: {}", exchange.getRequest().getHeaders());

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.info("Incoming Authorization Header: {}", authHeader);
        // Extract the JWT from the Authorization header
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        log.info("authorizationHeader from gateway " + authorizationHeader);

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token part

            // Decode the JWT token (validates and extracts claims)
            Jwt jwt = jwtDecoder.decode(token);

            // Extract the username (or other claims) from the JWT
            String username = jwt.getClaimAsString("preferred_username");
            log.info("extracted username from gateway " + username);

            // Optionally: You can log or check claims here
            System.out.println("Extracted Username: " + username);

            // Mutate the request to add the username as a custom header (X-Username)
            exchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-Username", username)  // Add the username to request headers
                            .build())
                    .build();
        }

        // Continue with the request chain, passing the mutated request with the added header
        return chain.filter(exchange);
    }*/



