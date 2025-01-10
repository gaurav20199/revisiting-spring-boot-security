package com.revisit.springsecurity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Value("${jwks.uri}")
    private String jwksUri;
    @Bean
    public SecurityFilterChain oauthResourceServerFilterChain(HttpSecurity security) throws Exception {
        security.oauth2ResourceServer(customizer -> {
            customizer.jwt(customizer2 -> {
                customizer2.jwkSetUri(jwksUri);
                customizer2.jwtAuthenticationConverter(new CustomJwtAuthenticationTokenConverter());
            });
        });

        return security.formLogin(Customizer.withDefaults()).
                authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()).
                build();
    }
}
