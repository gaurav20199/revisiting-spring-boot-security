package com.revisit.springsecurity.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Value("${jwks.uri}")
    private String jwksUri;
    @Bean
    public SecurityFilterChain oauthResourceServerFilterChain(HttpSecurity security) throws Exception {
        security.oauth2ResourceServer(
            //c-> c.authenticationManagerResolver(authenticationManagerResolver())
            c-> c.authenticationManagerResolver(jwtAuthenticationManagerResolver(jwtDecoder(),opaqueTokenIntrospector()))
             // c-> c.opaqueToken(op->tokenIntrospector())

        );

        return security.formLogin(Customizer.withDefaults()).
                authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()).
                build();
    }

/*    @Bean
    public OpaqueTokenIntrospector tokenIntrospector() {
        OpaqueTokenIntrospector introspector1 = new SpringOpaqueTokenIntrospector(
                "http://localhost:2020/oauth2/introspect", "client", "secret");

        OpaqueTokenIntrospector introspector2 = new SpringOpaqueTokenIntrospector(
                "http://localhost:1010/oauth2/introspect", "client", "secret");

        return new CompositeOpaqueTokenIntrospector(introspector1, introspector2);
    }*/

/*

    If we know that all the auth servers will be using JWT then we can set up the configurations in this way as well

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> jwtAuthenticationManagerResolver() {
        JwtIssuerAuthenticationManagerResolver jwtAuthManagerResolver = JwtIssuerAuthenticationManagerResolver.
                fromTrustedIssuers("http://localhost:1010", "http://localhost:2020");
        //these are the issuer location we can check them in the openid configurations url which is exposed.
        return jwtAuthManagerResolver;
    }

*/

    public AuthenticationManagerResolver<HttpServletRequest> jwtAuthenticationManagerResolver(
            JwtDecoder decoder,OpaqueTokenIntrospector introspector
    ) {
        AuthenticationManager jwtAuth = new ProviderManager(
                new JwtAuthenticationProvider(decoder)
        );
        AuthenticationManager opaqueAuth = new ProviderManager(
                new OpaqueTokenAuthenticationProvider(introspector)
        );

        return (request) -> {
                if("jwt".equals(request.getHeader("type")))
                    return jwtAuth;
                else
                    return opaqueAuth;
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri("http://localhost:1010/oauth2/jwks").build();
    }

    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector() {
        return new SpringOpaqueTokenIntrospector("http://localhost:2020/oauth2/introspect","client","secret");
    }

}
