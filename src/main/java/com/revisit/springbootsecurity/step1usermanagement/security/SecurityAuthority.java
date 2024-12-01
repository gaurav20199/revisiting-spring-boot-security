package com.revisit.springbootsecurity.step1usermanagement.security;

import com.revisit.springbootsecurity.step1usermanagement.Authority;
import org.springframework.security.core.GrantedAuthority;

public class SecurityAuthority implements GrantedAuthority {

    private final Authority authority;

    SecurityAuthority(Authority authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority.getAuthorityName();
    }
}
