package com.revisit.springbootsecurity.config.filters;

import com.revisit.springbootsecurity.config.authentication.CustomAuthentication;
import com.revisit.springbootsecurity.config.manager.CustomAuthenticationManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final CustomAuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(CustomAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // creating authentication object which is not yet authenticated(this will be created for every request)
        String key = request.getHeader("key");
        CustomAuthentication authentication = new CustomAuthentication(false,key);
        //Delegate the authentication object to the manager.
        Authentication authenticationObj = authenticationManager.authenticate(authentication);

        // Retrieve the object from Manager. If object is authenticated then set object in security context and
        // proceed with filter propagation
        if(authenticationObj.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authenticationObj);
            filterChain.doFilter(request,response);
        }




    }
}
