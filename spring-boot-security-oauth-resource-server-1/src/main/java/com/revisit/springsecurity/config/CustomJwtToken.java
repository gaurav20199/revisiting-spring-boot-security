package com.revisit.springsecurity.config;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;

public class CustomJwtToken extends JwtAuthenticationToken {

    private String field1ToAdd;
    private String field2ToAdd;
    public CustomJwtToken(Jwt jwt, List<SimpleGrantedAuthority> simpleGrantedAuthorities) {
        super(jwt,simpleGrantedAuthorities);
        field1ToAdd = "field1 is a part of token";
        field2ToAdd = "field2 is apart of token";
    }
}
