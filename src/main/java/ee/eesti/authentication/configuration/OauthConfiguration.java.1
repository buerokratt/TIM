package ee.eesti.authentication.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.apache.commons.lang3.StringUtils.defaultString;

@Configuration
@EnableOAuth2Client
public class OauthConfiguration {
    private static final String REGISTRATION_ID = "tara";

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            @Value("${security.oauth2.client.user-authorization-uri}")
            String authorizationUri,
            @Value("${security.oauth2.client.client-id}")
            String clientId,
            @Value("${security.oauth2.client.client-id}")
            String clientName,
            @Value("${security.oauth2.client.client-secret}")
            String clientSecret,
            @Value("${security.oauth2.client.registered-redirect-uri}")
            String redirectUrlTemplate,
            @Value("${security.oauth2.client.access-token-uri}")
            String tokenUri,
            @Value("${security.oauth2.resource.jwk.key-set-uri}")
            String jwkSetUri,
            @Value("${security.oauth2.client.scope}")
            String scope) {
        return new InMemoryClientRegistrationRepository(
                ClientRegistration
                        .withRegistrationId(REGISTRATION_ID)
                        .authorizationUri(authorizationUri)
                        .clientId(clientId)
                        .clientName(clientName)
                        .clientSecret(clientSecret)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri(redirectUrlTemplate)
                        .tokenUri(tokenUri)
                        .jwkSetUri(jwkSetUri)
                        .scope(defaultString(scope).split("[\\s]+"))
                        .build());
    }
}
