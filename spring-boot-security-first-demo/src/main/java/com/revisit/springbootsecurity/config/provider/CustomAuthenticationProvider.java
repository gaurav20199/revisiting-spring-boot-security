package com.revisit.springbootsecurity.config.provider;

import com.revisit.springbootsecurity.config.authentication.CustomAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Value("${secret.key}")
    private String secret;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;
        String secretFromRequestHeaders = customAuthentication.getKey();
        if(secretFromRequestHeaders.equals(secret))
            return new CustomAuthentication(true,secretFromRequestHeaders);

        throw new BadCredentialsException("Api Key is invalid!!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.equals(authentication);
    }
}
