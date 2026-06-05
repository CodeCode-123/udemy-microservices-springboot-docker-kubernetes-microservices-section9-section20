package com.eazybytes.gatewayserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Value("${spring.security.oauth2.resourceserver.jwt.jwt-set-uri}")
    private String jwtSetUri;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity serverHttpSecurity) {
        serverHttpSecurity.authorizeExchange(exchanges -> exchanges
                //if the method is GET, permit all without authentication
                        .pathMatchers(HttpMethod.GET).permitAll()
                //if the URI is /accounts, /cards, /loans, requires authentication, except for the GET methods
                .pathMatchers("/eazybank/accounts/**").authenticated()
                .pathMatchers("/eazybank/cards/**").authenticated()
                .pathMatchers("/eazybank/loans/**").authenticated())
                .oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                        .jwt(Customizer.withDefaults()));
        //csrf protection is required when use frontend browser, otherwise, GET, POST, PUT, PATCH, DELETE
        //methods will fail due to not handle csrf protection
        serverHttpSecurity.csrf(ServerHttpSecurity.CsrfSpec::disable);
        return serverHttpSecurity.build();
    }

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        //KeyCloak uses Asymmetric algorithm RS256 to sign JWTs
        //the jwt-set-uri is used to get the Public Key
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwtSetUri).build();
    }
}
