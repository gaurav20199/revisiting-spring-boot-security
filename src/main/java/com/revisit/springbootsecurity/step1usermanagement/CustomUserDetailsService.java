package com.revisit.springbootsecurity.step1usermanagement;

import com.revisit.springbootsecurity.step1usermanagement.security.SecurityUser;
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
        Optional<User> fetchedUser = userRepository.findUserByUserName(username);
        return fetchedUser.map(SecurityUser::new).orElseThrow(() -> new UsernameNotFoundException("User with:"+username+ " not found"));
    }
}
