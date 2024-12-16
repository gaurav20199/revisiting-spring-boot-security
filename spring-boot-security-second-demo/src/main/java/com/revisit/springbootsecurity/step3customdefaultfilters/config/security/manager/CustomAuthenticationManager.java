package com.revisit.springbootsecurity.step3customdefaultfilters.config.security.manager;

import com.revisit.springbootsecurity.step3customdefaultfilters.config.authentication.CustomAuthenticationObj;
import com.revisit.springbootsecurity.step3customdefaultfilters.config.security.provider.CustomApiKeyAuthProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class CustomAuthenticationManager implements AuthenticationManager {

    private final String key;

    public CustomAuthenticationManager(String key) {
        this.key = key;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // here we can have multiple providers
        CustomApiKeyAuthProvider authProvider = new CustomApiKeyAuthProvider(key);
        if(authProvider.supports(authentication.getClass())) {
            return authProvider.authenticate(authentication);
        }

        return authentication;
    }
}
