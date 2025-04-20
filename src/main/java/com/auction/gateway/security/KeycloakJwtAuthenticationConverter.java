package com.auction.gateway.security;


import jakarta.validation.constraints.NotNull;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import reactor.core.publisher.Mono;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String ACCOUNT = "account";
    private static final String ROLES = "roles";

    @Override
    public Mono<AbstractAuthenticationToken> convert(@NotNull Jwt source) {
        System.out.println("JWT Claims: " + source.getClaims());

        var authorities = Stream.concat(
                new JwtGrantedAuthoritiesConverter().convert(source).stream(),
                extractResourceRoles(source).stream()
        ).collect(Collectors.toSet());

        return Mono.just(new JwtAuthenticationToken(source, authorities));
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim(RESOURCE_ACCESS);

        if (resourceAccess == null || !resourceAccess.containsKey(ACCOUNT)) {
            return Collections.emptySet();
        }

        Map<String, List<String>> accountRoles = (Map<String, List<String>>) resourceAccess.get(ACCOUNT);
        List<String> roles = accountRoles.get(ROLES);

        if (roles == null || roles.isEmpty()) {
            return Collections.emptySet();
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.replace("-", "_").toUpperCase()))
                .collect(Collectors.toSet());
    }
}