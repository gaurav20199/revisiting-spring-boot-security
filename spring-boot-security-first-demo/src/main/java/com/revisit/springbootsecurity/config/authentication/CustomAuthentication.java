package com.revisit.springbootsecurity.config.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

public class CustomAuthentication implements Authentication {

    private final boolean isAuthenticated;
    private final String key;

    public CustomAuthentication(boolean isAuthenticated,String key){
        this.isAuthenticated = isAuthenticated;
        this.key = key;
    }
    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }



    @Override
    public String getName() {
        return null;
    }

    public String getKey() {
        return key;
    }
}
