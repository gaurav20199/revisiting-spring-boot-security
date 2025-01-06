package com.revisit.springsecurity.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Entity
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    private String clientId;

    private String secret;

    private String redirectUri;

    private String scope;

    private String grantType;

    private String authMethod;

    public long getId() {
        return id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public static Client from(RegisteredClient registeredClient) {
        Client client = new Client();
        client.setClientId(registeredClient.getClientId());
        client.setSecret(registeredClient.getClientSecret());
        client.setAuthMethod(registeredClient.getAuthorizationGrantTypes().stream().findFirst().get().getValue());
        client.setRedirectUri(registeredClient.getRedirectUris().stream().findFirst().get());
        client.setScope(registeredClient.getScopes().stream().findFirst().get());
        return client;
    }

    public static RegisteredClient from(Client client) {
        return RegisteredClient.withId(String.valueOf(client.getId())).
                clientId(client.getClientId()).
                scope(client.getScope()).
                clientSecret(client.getSecret()).
                clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuthMethod())).
                authorizationGrantType(new AuthorizationGrantType(client.getGrantType())).
                redirectUri(client.getRedirectUri()).build();

    }
}
