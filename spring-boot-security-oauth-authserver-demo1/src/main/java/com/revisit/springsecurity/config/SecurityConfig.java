package com.revisit.springsecurity.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class SecurityConfig {

    // url: localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://spring.io
    // url with PKCE: localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://spring.io&code_challenge=gFbazbPLZu8pbeicMaoFyyJGfPZWiF7dOMdvbY13qMg&code_challenge_method=S256

    /*
        curl --location 'localhost:8080/oauth2/token' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
--header 'Cookie: JSESSIONID=13D78AD5F27CBD340651906D2903580E' \
--form 'code="gONj_bRKthyCTdrE1DHmbihojRMRvH29TFmh8AA2IhS_gprLNnlWiRVorP8ZDVVFSoYnNGxtXNKB-bL2IOfOeKXs9QF-Vtnfyuq7u7pkLWFt3VTHe8kKan4JtaXxndaw"' \
--form 'grant_type="authorization_code"' \
--form 'client_id="client"' \
--form 'redirect_uri="https://spring.io"'

WITH PKCE
curl --location 'localhost:8080/oauth2/token' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
--header 'Cookie: JSESSIONID=13D78AD5F27CBD340651906D2903580E; JSESSIONID=13D78AD5F27CBD340651906D2903580E' \
--form 'code="4OAG4jp5mmd58qkLDTT6xFrGQanjyMy9uDZP9iYJnT2dkyPYOn-RDPcRGHTlVck2xcaPqB-_414PqVg_jQjGXG_Fk5llncn4fv1ybhf0tWHlMS9VdQII0u002Z3u5u-D"' \
--form 'grant_type="authorization_code"' \
--form 'client_id="client"' \
--form 'redirect_uri="https://spring.io"' \
--form 'code_verifier="x3NPjHeE_rHfnoJJT1XBAfgQEx4SCnzPqleH2cMsTuRHeMngAOmn5R1pMbeW4G-ZnhVFjBDfM9iJxFNQ1MNex_1YuLmzjZ7X3x2BZpDw-9lzp4zy1T3b_mGar2vaDHut"'

Basic auth is required in above post request where client username and credentials needs to be shared

Endpoint exposing all the standard openid configurations of any authorization server supporting open id connect
localhost:8080/.well-known/openid-configuration
     */
    @Bean
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity security) throws Exception {
        // applyDefaultSecurity method got deprecated since oauth1.4.0 spring authorization server
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer()
                        .authorizationEndpoint(a -> {
                             a.authenticationProviders(authenticationProviders -> {
                               for(AuthenticationProvider provider:authenticationProviders) {
                                   if(provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider) {
                                       OAuth2AuthorizationCodeRequestAuthenticationProvider p = (OAuth2AuthorizationCodeRequestAuthenticationProvider) provider;
                                       p.setAuthenticationValidator(new CustomRedirectUriValidator());
                                   }

                               }
                             });
                        })
                        .oidc(Customizer.withDefaults());

        security
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                .exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return security.build();
    }

    @Bean
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity security) throws Exception {
        return security.formLogin(Customizer.withDefaults()).
                authorizeHttpRequests(customizer -> customizer.anyRequest().authenticated()).
                build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
        UserDetails userDetails = User.withUsername("gaurav").password("{noop}gaurav").authorities("read").build();
        userDetailsManager.createUser(userDetails);
        return userDetailsManager;
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString()).
                clientId("client").
                clientSecret("{noop}secret").
                scope(OidcScopes.OPENID).
                scope(OidcScopes.PROFILE).
                redirectUri("https://spring.io").
                clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).
                authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).
                authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .tokenSettings(
//                        TokenSettings.builder().
//                                accessTokenTimeToLive(Duration.ofSeconds(9000)).
//                                accessTokenFormat(OAuth2TokenFormat.REFERENCE).    // opaque token
//                                build()
//                )
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> {
            context.getClaims().claim("dummyKey","dummyValue");
        };
    }

    /*
        * If we want to use our own keys and not depend on default we can do customization as well
        * Only for reference purpose
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA");
        kpGenerator.initialize(2048);
        KeyPair keyPair = kpGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }
     */
}
