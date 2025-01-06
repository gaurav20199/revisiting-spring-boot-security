package com.revisit.springsecurity.services;

import com.revisit.springsecurity.entities.User;
import com.revisit.springsecurity.model.SecurityUser;
import com.revisit.springsecurity.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> fetchedUser = userRepository.findByUserName(username);
        return fetchedUser.map(user -> new SecurityUser(user)).orElseThrow(()-> new UsernameNotFoundException("User name not found"));
    }
}
