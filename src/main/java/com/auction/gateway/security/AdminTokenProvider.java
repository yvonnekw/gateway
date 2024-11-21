package com.auction.gateway.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.core.ParameterizedTypeReference;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Component
@EnableScheduling
@Slf4j
@RequiredArgsConstructor
public class AdminTokenProvider {

    private final RestTemplate restTemplate;

   // @Value("${CLIENT_ID}")
    private final String clientId = "auction-client";

    //@Value("${CLIENT_SECRET}")
    private final String clientSecret = "4fLoRVTTU7Hu7S1iBY2FNwPY7zYJYM77";

   // @Value("${ADMIN_USERNAME}")
    private final String username = "adminsmith";

    //@Value("${ADMIN_PASSWORD}")
    private final String password = "adminPassword";
    //@Value("${KEYCLOAK_LOGIN}")
   //private String tokenUrl;

    private final String tokenUrl = "http://localhost:9098/realms/auction-realm/protocol/openid-connect/token";

    private final AtomicReference<String> adminToken = new AtomicReference<>();
    private long tokenExpiryTime;

    public AdminTokenProvider() {
        this.restTemplate = new RestTemplate();
        try {
            log.info("Initializing AdminTokenProvider with clientId: {}, tokenUrl: {}", clientId, tokenUrl);
            if (clientId == null || clientSecret == null || tokenUrl == null) {
                throw new IllegalArgumentException("One or more configuration properties are missing.");
            }
            refreshAdminToken();  // Will throw an exception if something goes wrong
        } catch (Exception e) {
            log.error("Error initializing AdminTokenProvider: ", e);
            throw new RuntimeException("Failed to initialize AdminTokenProvider", e);
        }
    }

    public String getAdminToken() {
        return adminToken.get();
    }

    @Scheduled(fixedRate = 60000) // Check every minute
    public void scheduledTokenRefresh() {
        if (isTokenExpired()) {
            log.info("Admin token is expired or about to expire. Refreshing...");
            refreshAdminToken();
        }
    }

    private boolean isTokenExpired() {
        return System.currentTimeMillis() >= tokenExpiryTime - 60000; // Refresh 1 minute before expiry
    }

    public void refreshAdminToken() {
        try {
            log.info("Using token URL: {}", tokenUrl);
            log.info("Using client id: {}", clientId);
            log.info("Using username: {}", username);


            // If the tokenUrl is null or empty, throw an exception
            if (tokenUrl == null || tokenUrl.isEmpty()) {
                throw new IllegalArgumentException("Token URL is not set properly!");
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("grant_type", "password");
            body.add("username", username);
            body.add("password", password);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            Map<String, Object> response = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    request,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            ).getBody();

            adminToken.set((String) response.get("access_token"));
            Integer expiresIn = (Integer) response.get("expires_in");
            tokenExpiryTime = System.currentTimeMillis() + (expiresIn * 1000L);

            log.info("Admin token refreshed successfully. Expires in {} seconds.", expiresIn);
        } catch (Exception e) {
            log.error("Failed to fetch admin token", e);
            throw new RuntimeException("Failed to fetch admin token", e);
        }
    }
}


/*
@Component
@EnableScheduling
@Slf4j
@RequiredArgsConstructor
public class AdminTokenProvider {

    private final RestTemplate restTemplate;

    @Value("${CLIENT_ID}")
    private String clientId;

    @Value("${CLIENT_SECRET}")
    private String clientSecret;

    @Value("${ADMIN_USERNAME}")
    private String username;

    @Value("${ADMIN_PASSWORD}")
    private String password;

    @Value("${KEYCLOAK_LOGIN}")
    private String tokenUrl;

    private final AtomicReference<String> adminToken = new AtomicReference<>();
    private long tokenExpiryTime;

    public AdminTokenProvider() {
        this.restTemplate = new RestTemplate();
        try {
            log.info("Initializing AdminTokenProvider with clientId: {}, tokenUrl: {}", clientId, tokenUrl);
            refreshAdminToken();  // Will throw an exception if something goes wrong
        } catch (Exception e) {
            log.error("Error initializing AdminTokenProvider: ", e);
            throw new RuntimeException("Failed to initialize AdminTokenProvider", e);
        }
    }

    public String getAdminToken() {
        return adminToken.get();
    }

    @Scheduled(fixedRate = 60000) // Check every minute
    public void scheduledTokenRefresh() {
        if (isTokenExpired()) {
            log.info("Admin token is expired or about to expire. Refreshing...");
            refreshAdminToken();
        }
    }

    private boolean isTokenExpired() {
        return System.currentTimeMillis() >= tokenExpiryTime - 60000; // Refresh 1 minute before expiry
    }

    public void refreshAdminToken() {
        try {
            log.info("Using token URL: {}", tokenUrl);

            // If the tokenUrl is null or empty, throw an exception
            if (tokenUrl == null || tokenUrl.isEmpty()) {
                throw new IllegalArgumentException("Token URL is not set properly!");
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("grant_type", "password");
            body.add("username", username);
            body.add("password", password);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            Map<String, Object> response = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    request,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            ).getBody();

            adminToken.set((String) response.get("access_token"));
            Integer expiresIn = (Integer) response.get("expires_in");
            tokenExpiryTime = System.currentTimeMillis() + (expiresIn * 1000L);

            log.info("Admin token refreshed successfully. Expires in {} seconds.", expiresIn);
        } catch (Exception e) {
            log.error("Failed to fetch admin token", e);
            throw new RuntimeException("Failed to fetch admin token", e);
        }
    }
}
*/

/*
@Component
@EnableScheduling
@Slf4j
@RequiredArgsConstructor
public class AdminTokenProvider {

    private final RestTemplate restTemplate;

    @Value("${CLIENT_ID}")
    private String clientId;

    @Value("${CLIENT_SECRET}")
    private String clientSecret;

    @Value("${ADMIN_USERNAME}")
    private String username;

    @Value("${ADMIN_PASSWORD}")
    private String password;

    @Value("${KEYCLOAK_LOGIN}")
    private String tokenUrl;

    private final AtomicReference<String> adminToken = new AtomicReference<>();
    private long tokenExpiryTime;

    public AdminTokenProvider() {
        this.restTemplate = new RestTemplate();
        refreshAdminToken();
    }

    public String getAdminToken() {
        return adminToken.get();
    }

    @Scheduled(fixedRate = 60000) // Check every minute
    public void scheduledTokenRefresh() {
        if (isTokenExpired()) {
            log.info("Admin token is expired or about to expire. Refreshing...");
            refreshAdminToken();
        }
    }

    private boolean isTokenExpired() {
        return System.currentTimeMillis() >= tokenExpiryTime - 60000; // Refresh 1 minute before expiry
    }

    public void refreshAdminToken() {
        log.info("Using token URL: {}", tokenUrl);
        try {
            // Ensure tokenUrl is absolute (complete URL with http:// or https://)
            log.info("Token URL: {}", tokenUrl);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("grant_type", "password");
            body.add("username", username);
            body.add("password", password);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            // Using exchange with ParameterizedTypeReference for type safety
            Map<String, Object> response = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    request,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            ).getBody();

            adminToken.set((String) response.get("access_token"));
            Integer expiresIn = (Integer) response.get("expires_in");
            tokenExpiryTime = System.currentTimeMillis() + (expiresIn * 1000L);

            log.info("Admin token refreshed successfully. Expires in {} seconds.", expiresIn);
        } catch (Exception e) {
            log.error("Failed to fetch admin token", e);
            throw new RuntimeException("Failed to fetch admin token", e);
        }
    }
}



 */
/*

package com.auction.gateway.security;

import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;


import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Component
@EnableScheduling
@Slf4j
@RequiredArgsConstructor
public class AdminTokenProvider {

    private final RestTemplate restTemplate;

    @Value("${CLIENT_ID}")
    private String clientId;

    @Value("${CLIENT_SECRET}")
    private String clientSecret;

    @Value("${ADMIN_USERNAME}")
    private String username;

    @Value("${ADMIN_PASSWORD}")
    private String password;

    @Value("${KEYCLOAK_LOGIN}")
    private String tokenUrl;

    private final AtomicReference<String> adminToken = new AtomicReference<>();
    private long tokenExpiryTime;

    public AdminTokenProvider() {
        this.restTemplate = new RestTemplate();
        refreshAdminToken();
    }

    public String getAdminToken() {
        return adminToken.get();
    }

    @Scheduled(fixedRate = 60000) // Check every minute
    public void scheduledTokenRefresh() {
        if (isTokenExpired()) {
            log.info("Admin token is expired or about to expire. Refreshing...");
            refreshAdminToken();
        }
    }

    private boolean isTokenExpired() {
        return System.currentTimeMillis() >= tokenExpiryTime - 60000; // Refresh 1 minute before expiry
    }

    public void refreshAdminToken() {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("grant_type", "password");
            body.add("username", username);
            body.add("password", password);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            Map<String, Object> response = restTemplate.postForObject(tokenUrl, request, Map.class);
            adminToken.set((String) response.get("access_token"));
            Integer expiresIn = (Integer) response.get("expires_in");
            tokenExpiryTime = System.currentTimeMillis() + (expiresIn * 1000L);

            log.info("Admin token refreshed successfully. Expires in {} seconds.", expiresIn);
        } catch (Exception e) {
            log.error("Failed to fetch admin token", e);
            throw new RuntimeException("Failed to fetch admin token", e);
        }
    }
}

*/