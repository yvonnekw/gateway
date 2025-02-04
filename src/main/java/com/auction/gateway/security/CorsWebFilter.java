package com.auction.gateway.security;

import lombok.extern.slf4j.Slf4j;


@Slf4j
//@Component
public class CorsWebFilter  {
/*
   // @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Log the method and headers of the request
        log.info("Handling CORS for request method: {}", exchange.getRequest().getMethod().name());

        // Add CORS headers to the response
        exchange.getResponse().getHeaders().add("Access-Control-Allow-Origin", "http://localhost:4200"); // Allow only specific origin for security
        exchange.getResponse().getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        exchange.getResponse().getHeaders().add("Access-Control-Allow-Headers", "Authorization, Content-Type");
        exchange.getResponse().getHeaders().add("Access-Control-Allow-Credentials", "true");

        // If the request method is OPTIONS, return a 200 response to handle pre-flight requests
        if (HttpMethod.OPTIONS.equals(exchange.getRequest().getMethod())) {
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);  // Continue the request-response cycle
    }
    */
}

