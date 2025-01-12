package com.revisit.springsecurity.services;

import com.revisit.springsecurity.entities.Client;
import com.revisit.springsecurity.repositories.ClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class CustomClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    public CustomClientService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.save(Client.from(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        Optional<Client> clientById = clientRepository.findById(Long.parseLong(id));
        return clientById.map(client -> Client.from(client)).orElseThrow();
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Optional<Client> clientById = clientRepository.findByClientId(clientId);
        return clientById.map(client -> Client.from(client)).orElseThrow();
    }
}
