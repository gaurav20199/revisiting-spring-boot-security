package com.revisit.springbootsecurity.step1usermanagement;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findUserByUserName(String userName);
}
