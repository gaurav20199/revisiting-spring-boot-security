package com.revisit.springbootsecurity.config;

import com.revisit.springbootsecurity.config.filters.CustomAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class WebSecurityConfig {

    private final CustomAuthenticationFilter customAuthenticationFilter;

   public WebSecurityConfig(CustomAuthenticationFilter customAuthenticationFilter) {
        this.customAuthenticationFilter = customAuthenticationFilter;
    }

//    @Bean("inMemoryUserDetailsManager")
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
//        UserDetails user = User.withUsername("gaurav").password("gaurav").authorities("user").build();
//        userDetailsManager.createUser(user);
//        return userDetailsManager;
//    }

    // for step2 custom authentication
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {
        return security
                .addFilterAt(customAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // add custom filter where user and password authentication filter lies
                .authorizeHttpRequests(customizer ->customizer.anyRequest().authenticated())
                .build();
    }

    @Bean("noopPasswordEncoder")
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}
