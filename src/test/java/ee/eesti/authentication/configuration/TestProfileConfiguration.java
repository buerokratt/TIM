package ee.eesti.authentication.configuration;

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;

@Configuration
@Profile("mock")
public class TestProfileConfiguration {

    @Bean
    @Primary
    public OAuth2AccessTokenResponseClient<?> mockedAccessTokenResponseClient() {
        return Mockito.mock(OAuth2AccessTokenResponseClient.class);
    }

    @Bean
    @Primary
    public JwtDecoder jwtDecoder() {
        return Mockito.mock(JwtDecoder.class);
    }

    // The OIDC login flow doesn't decode ID tokens with the plain JwtDecoder bean above - it looks up
    // a JwtDecoderFactory<ClientRegistration> bean (defaulting to OidcIdTokenDecoderFactory, which does
    // a real JWKS fetch + JWT parse, if none is found). Without this, every OIDC login test would try to
    // parse the mocked access-token response's literal "ID" id_token as a real JWT and fail.
    @Bean
    @Primary
    public JwtDecoderFactory<ClientRegistration> jwtDecoderFactory(JwtDecoder jwtDecoder) {
        return registration -> jwtDecoder;
    }
}
