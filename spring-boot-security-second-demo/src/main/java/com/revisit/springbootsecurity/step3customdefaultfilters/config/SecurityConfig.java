package com.revisit.springbootsecurity.step3customdefaultfilters.config;

import com.revisit.springbootsecurity.step3customdefaultfilters.config.security.filters.ApiKeyFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Value("${secret}")
    private String secret;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {
        return security
                .addFilterBefore(new ApiKeyFilter(secret), BasicAuthenticationFilter.class)
                //.authenticationManager() this overrides the default authentication manager
                //.authenticationProvider() this doesn't override(s) the default AP. It adds one more to the AP list
                .authorizeHttpRequests(c -> c.anyRequest().authenticated())
                .build();
    }
}
