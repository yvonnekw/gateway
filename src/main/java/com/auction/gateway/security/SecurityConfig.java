package com.auction.gateway.security;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;


//@Configuration
//@EnableWebSecurity
@EnableWebFluxSecurity
//@EnableMethodSecurity//(securedEnabled = true)
@RequiredArgsConstructor
@Configuration
//EnableWebSecurity
public class SecurityConfig  {

    // "/api/v1/products/get-all-products", "/api/v1/users/create-user"
   /*
    private final String[] freeResourceUrls = {
            "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/swagger-resources/**",
            "/api-docs/**", "/aggregate/**", "/eureka/**",  "/user-service/swagger-ui/**",

    };*/

    private static final String[] PUBLIC_ENDPOINTS = {
            "/api/v1/products/get-all-products",
            "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**",
            "/swagger-resources/**", "/api-docs/**", "/aggregate/**",
            "/eureka/**", "/user-service/swagger-ui/**"
    };

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(token -> token.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())));

        return serverHttpSecurity.build();
    }

    /*
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
*/
/*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(PUBLIC_ENDPOINTS)
                        .permitAll()
                        .anyExchange().hasRole("user")
                        .anyExchange()
                        //.antMatchers("/api/v1/products/**").hasRole("user")
                        .authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(token -> token.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())));

        return serverHttpSecurity.build();

    }
*/
/*
    @Bean
    public  SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
       return httpSecurity.authorizeHttpRequests(authorize -> authorize.anyRequest()
                .authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }
*/

/*
    //@Autowired
    private  final Converter jwtAuthConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests(authorize -> {
            authorize
                    .requestMatchers(HttpMethod.GET, "/api/v1/products/get-all-products").permitAll()
                   // .requestMatchers()
                    .anyRequest().authenticated();
        });
        http.oauth2ResourceServer(t -> {
            t.jwt(configurer -> configurer.jwtAuthenticationConverter(jwtAuthConverter));
        });
        http.sessionManagement(
                t -> t.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        return http.build();
    }
*/




/*
    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        // Configure the ReactiveJwtDecoder using the Keycloak URL
        return JwtDecoders.fromIssuerLocation("http://localhost:9098/realms/auction-realm");
    }*/

/*
    //jwt quth
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests(authorize -> {
            authorize.anyRequest().authenticated();
        });
        http.oauth2ResourceServer(t -> {
            t.opaqueToken(Customizer.withDefaults());
        });
        http.sessionManagement(
                t -> t.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        return http.build();
    }

*/

    //@Override





    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/api/v1/products/get-all-products", "/swagger-ui/**", "/v3/api-docs/**")
                        .permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt());

        return http.build();
    }


*/
}
/*

}
*/

   // public static final String ADMIN = "admin";
   // public static final String USER = "user";

    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(authz -> authz
                        .pathMatchers(PUBLIC_ENDPOINTS).permitAll() // Public endpoints
                        .anyExchange().authenticated() // All other requests require authentication
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter())) // JWT converter
                )
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // Disable sessions

        return http.build();
    }


    // Custom JWT converter (reactive)
// Custom JWT converter (reactive)
    private Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtConverter() {
        return jwt -> {
            // Create authorities from JWT claims
            Collection<GrantedAuthority> authorities = Stream.concat(
                    new JwtGrantedAuthoritiesConverter().convert(jwt).stream(),
                    jwt.getClaimAsStringList("roles").stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
            ).collect(Collectors.toSet());

            // Return a Mono of JwtAuthenticationToken
            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        };
    }

}

*/

    /*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authz) ->
                authz.requestMatchers(HttpMethod.GET, "/api/v1/products/get-all-products").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/admin/**").hasRole(ADMIN)
                        .requestMatchers(HttpMethod.GET, "/api/user/**").hasRole(USER)
                        .requestMatchers(HttpMethod.GET, "/api/admin-and-user/**").hasAnyRole(ADMIN,USER)
                        .anyRequest().authenticated());

        http.sessionManagement(sess -> sess.sessionCreationPolicy(
                SessionCreationPolicy.STATELESS));
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter)));

        return http.build();
    }
*/
    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(PUBLIC_ENDPOINTS) // Public endpoints, no auth required
                        .permitAll()
                        .anyExchange() // All other endpoints require authentication
                        .authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt()); // Set up JWT authentication for secured endpoints

        return serverHttpSecurity.build();
    }*/


    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(PUBLIC_ENDPOINTS)
                        .permitAll()
                        .anyExchange()
                        .authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(token -> token.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())));

        return serverHttpSecurity.build();

    }
    */


/*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange()
                .pathMatchers(HttpMethod.GET).permitAll()  // Allow GET requests without authentication
                .pathMatchers(PUBLIC_ENDPOINTS).permitAll()   // Allow public paths without authentication
                .anyExchange().authenticated()  // Require authentication for all other endpoints
                .and()
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())) // JWT converter
                );

        return http.build();
    }
}
*/

    /*

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(PUBLIC_ENDPOINTS)
                        .permitAll()
                        .anyExchange()
                        .authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(token -> token.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())));

        return serverHttpSecurity.build();

    }
}
*/



/*

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()  // Public endpoints
                        .requestMatchers("/admin/**").hasRole("ADMIN")  // Admin endpoints
                        .anyRequest().authenticated()  // All other endpoints require authentication
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwtConfigurer ->
                                jwtConfigurer.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter()) // Use the custom converter
                        )
                );

        return http.build();

    }*/
    /*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Configure security
        http
                .csrf().disable()
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/products/get-all-products").permitAll()
                        .requestMatchers(freeResourceUrls).permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt()
                );
        return http.build();
    }
*/
    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration corsConfig = new CorsConfiguration();
                    corsConfig.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
                    corsConfig.setAllowCredentials(true);
                    return corsConfig;
                }))
                .authorizeExchange(exchange -> exchange
                        // Allow all GET requests without authentication
                        .pathMatchers(HttpMethod.GET, "/**").permitAll()
                        // Allow access to specific free resources
                        .pathMatchers(freeResourceUrls).permitAll()
                        // Restrict access to admin resources to users with the ADMIN role
                        //.pathMatchers(adminResources).hasRole("ADMIN")
                        // Authenticate all other requests
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter()))
                );

        return serverHttpSecurity.build();
    }*/
    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration corsConfig = new CorsConfiguration();
                    corsConfig.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
                    corsConfig.setAllowCredentials(true);
                    return corsConfig;
                }))
                .authorizeExchange(exchange -> exchange
                        // Explicitly allow access to free resource URLs
                        .pathMatchers(freeResourceUrls).permitAll()
                        // All other endpoints require authentication
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter()))
                );

        return serverHttpSecurity.build();
    }
*/
    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration corsConfig = new CorsConfiguration();
                    corsConfig.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
                    corsConfig.setAllowCredentials(true);
                    return corsConfig;
                }))
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(freeResourceUrls).permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(jwt ->
                                jwt.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter()))
                );

        return serverHttpSecurity.build();
    }
    */

    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(freeResourceUrls).permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(jwt ->
                                jwt.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter()))
                );

        return serverHttpSecurity.build();
    }

*/

    /*
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(freeResourceUrls)
                        .permitAll()
                        .anyExchange()
                        .authenticated()
                )
                .oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt); // Enable JWT for OAuth2

        return http.build();
    }

    */
/*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeHttpRequests(req ->
                        req.requestMatchers(
                                     freeResourceUrls
                                )
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(token -> token.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())))

        return http.build();
    }
*/
/*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers(freeResourceUrls)
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwtConfigurer ->
                                jwtConfigurer.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())
                        )
                );

        return http.build();
    }
/*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeHttpRequests(req ->
                        req.requestMatchers(
                                     freeResourceUrls
                                )
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                )
                .oauth2ResourceServer(auth ->
                        auth.jwt(token -> token.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())))

        return http.build();
    }
*/
/*
            @Bean
            public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
                serverHttpSecurity
                        .csrf(ServerHttpSecurity.CsrfSpec::disable)
                        .authorizeExchange(exchange -> exchange
                                .pathMatchers(freeResourceUrls)
                                .permitAll()
                                .anyExchange()
                                .authenticated()
                        )
                        .oauth2ResourceServer(auth ->
                                auth.jwt(token -> token.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())))

                return serverHttpSecurity.build();

            }


        }


        return serverHttpSecurity.build();

    }
*/


