package com.revisit.springsecurity.repositories;

import com.revisit.springsecurity.entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client,Long> {

    Optional<Client> findByClientId(String clientId);
}
