package com.revisit.springsecurity.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Value("${jwks.uri}")
    private String jwksUri;
    @Bean
    public SecurityFilterChain oauthResourceServerFilterChain(HttpSecurity security) throws Exception {
        security.oauth2ResourceServer(
            c-> c.authenticationManagerResolver(authenticationManagerResolver())
        );
        return security.formLogin(Customizer.withDefaults()).
                authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()).
                build();
    }

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        JwtIssuerAuthenticationManagerResolver jwtAuthManagerResolver = JwtIssuerAuthenticationManagerResolver.
                fromTrustedIssuers("http://localhost:1010", "http://localhost:2020");
        //these are the issuer location we can check them in the openid configurations url which is exposed.
        return jwtAuthManagerResolver;
    }
}
