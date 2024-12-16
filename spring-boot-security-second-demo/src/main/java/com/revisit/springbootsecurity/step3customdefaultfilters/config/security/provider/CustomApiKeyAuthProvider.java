package com.revisit.springbootsecurity.step3customdefaultfilters.config.security.provider;

import com.revisit.springbootsecurity.step3customdefaultfilters.config.authentication.CustomAuthenticationObj;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class CustomApiKeyAuthProvider implements AuthenticationProvider {

    private final String key;

    public CustomApiKeyAuthProvider(String key) {
        this.key = key;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthenticationObj authenticationObj = (CustomAuthenticationObj) authentication;
        if(key.equals(authenticationObj.getSecret())) {
            authenticationObj.setAuthenticated(true);
            return authenticationObj;
        }
        throw new BadCredentialsException("Api Key is invalid");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthenticationObj.class.equals(authentication);
    }
}
