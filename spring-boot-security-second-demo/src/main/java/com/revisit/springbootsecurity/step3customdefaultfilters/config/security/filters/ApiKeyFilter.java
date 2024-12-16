package com.revisit.springbootsecurity.step3customdefaultfilters.config.security.filters;

import com.revisit.springbootsecurity.step3customdefaultfilters.config.authentication.CustomAuthenticationObj;
import com.revisit.springbootsecurity.step3customdefaultfilters.config.security.manager.CustomAuthenticationManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ApiKeyFilter extends OncePerRequestFilter {

    private final String secret;

    public ApiKeyFilter(String key) {
        this.secret = key;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestKey = request.getHeader("x-api-key");
        CustomAuthenticationManager manager = new CustomAuthenticationManager(secret);
        CustomAuthenticationObj obj = new CustomAuthenticationObj(requestKey);

        if(requestKey==null || requestKey.equals("null")) {
            filterChain.doFilter(request,response);
            return;
        }

        try {
            Authentication authenticatedObj = manager.authenticate(obj);
            if (authenticatedObj.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authenticatedObj);
                filterChain.doFilter(request,response);
            }
        }catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
