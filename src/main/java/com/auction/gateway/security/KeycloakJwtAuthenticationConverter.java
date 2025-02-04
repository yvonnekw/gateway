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
    public Mono<AbstractAuthenticationToken> convert(@NotNull Jwt jwt) {
        System.out.println("JWT Claims: " + jwt.getClaims());
        return Mono.just(
                new JwtAuthenticationToken(
                        jwt,
                        Stream.concat(
                                new JwtGrantedAuthoritiesConverter().convert(jwt).stream(),
                                extractResourceRoles(jwt).stream()
                        ).collect(Collectors.toSet())
                )
        );
    }


    /**
     * Extracts roles from the 'resource_access' claim in the JWT.
     *
     * @param jwt the JWT token.
     * @return a collection of granted authorities.
     */
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaimAsMap(RESOURCE_ACCESS);
        if (resourceAccess == null) {
            return Collections.emptySet();
        }

        Map<String, Object> accountAccess = (Map<String, Object>) resourceAccess.getOrDefault(ACCOUNT, Collections.emptyMap());
        List<String> roles = (List<String>) accountAccess.getOrDefault(ROLES, Collections.emptyList());

        if (roles.isEmpty()) {
            return Collections.emptySet();
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.replace("-", "_").toUpperCase()))
                .collect(Collectors.toSet());
    }
}

  /*
    @Override
    public Mono<AbstractAuthenticationToken> convert(@NotNull Jwt jwt) {
        return Mono.just(
                new JwtAuthenticationToken(
                        jwt,
                        Stream.concat(
                                new JwtGrantedAuthoritiesConverter().convert(jwt).stream(),
                                extractResourceRoles(jwt).stream()
                        ).collect(Collectors.toSet())
                )
        );
    }*/
    /*
    @Override
    public Mono<AbstractAuthenticationToken> convert(@NotNull Jwt jwt) {
        return Mono.just(
                new JwtAuthenticationToken(
                        jwt,
                        Stream.concat(
                                new JwtGrantedAuthoritiesConverter().convert(jwt).stream(),
                                extractResourceRoles(jwt).stream()
                        ).collect(toSet())
                )
        );
    }

    /**
     * Extracts roles from the 'resource_access' claim in the JWT.
     * @param jwt the JWT token.
     * @return a collection of granted authorities.
     */
    /*
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaimAsMap(RESOURCE_ACCESS);
        if (resourceAccess == null || !resourceAccess.containsKey(ACCOUNT)) {
            return Collections.emptySet();
        }

        Map<String, Object> accountAccess = (Map<String, Object>) resourceAccess.get(ACCOUNT);
        List<String> roles = (List<String>) accountAccess.get(ROLES);
        if (roles == null) {
            return Collections.emptySet();
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.replace("-", "_").toUpperCase()))
                .collect(toSet());
    }
}
*/
/*
public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String ACCOUNT = "account";
    private static final String ROLES = "roles";

    @Override
    public AbstractAuthenticationToken convert(@NotNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                new JwtGrantedAuthoritiesConverter().convert(jwt).stream(),
                extractResourceRoles(jwt).stream()
        ).collect(toSet());

        return new JwtAuthenticationToken(jwt, authorities);
    }

    /**
     * Extracts roles from the 'resource_access' claim in the JWT.
     * @param jwt the JWT token.
     * @return a collection of granted authorities.
     */

    /*
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaimAsMap(RESOURCE_ACCESS);
        if (resourceAccess == null || !resourceAccess.containsKey(ACCOUNT)) {
            return Collections.emptySet(); // No resource access or roles defined
        }

        Map<String, Object> accountAccess = (Map<String, Object>) resourceAccess.get(ACCOUNT);
        List<String> roles = (List<String>) accountAccess.get(ROLES);
        if (roles == null) {
            return Collections.emptySet(); // No roles defined in the account resource access
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.replace("-", "_").toUpperCase()))
                .collect(toSet());
    }
*/
    /*
    @Override
    public AbstractAuthenticationToken convert(@NotNull Jwt source) {
        return new JwtAuthenticationToken(
                source,
                Stream.concat(
                        new JwtGrantedAuthoritiesConverter().convert(source).stream(),
                        extractResourceRoles(source).stream()
                ).collect(toSet())

        );
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        var resourceAccess = new HashMap<>(jwt.getClaim("resource_access"));
        var eternal = (Map<String, List<String>>) resourceAccess.get("account");
        var roles = eternal.get("roles");

        return  roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.replace("-", "_")))
                .collect(toSet());
    }

    */
//}
