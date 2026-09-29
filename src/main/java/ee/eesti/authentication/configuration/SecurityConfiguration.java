package ee.eesti.authentication.configuration;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.controller.HeartBeatController;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.defaultString;

/**
 * OAuth security configuration
 * <p>
 * <p>
 * Note! Spring does seem to provide some default variables for oauth2 configuration.
 * <p>
 * Due to the lack of documentation, these standard variables might not work with different configurations.
 */
@Configuration
@Slf4j
@EnableWebSecurity(debug = false)
@PropertySources(@PropertySource(value = {"file:${tara-integration.properties}"}, ignoreResourceNotFound = true))
public class SecurityConfiguration {
    @Value("${frontpage.redirect.url}")
    private String frontPageRedirectUrl;
    @Value("${cors.allowedOrigins:*}")
    private String allowedOrigins;
    @Value("${headers.contentSecurityPolicy}")
    private String contentSecurityPolicy;
    @Value("${security.allowlist.jwt}")
    private String allowedJWTIps;

    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final CustomSessionAttributeSecurityFilter filter;
    private final JwtSignatureConfig jwtSignatureConfig;

    public SecurityConfiguration(JwtSignatureConfig jwtSignatureConfig,
                                 AuthenticationSuccessHandler authenticationSuccessHandler,
                                 CustomSessionAttributeSecurityFilter filter,
                                 @Lazy OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {
        this.jwtSignatureConfig = jwtSignatureConfig;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.filter = filter;
        this.accessTokenResponseClient = accessTokenResponseClient;
        log.info("SecurityConfiguration filter:"+ filter.toString());
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("SecurityConfiguration.filterChain:" + http );
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .disable())
                .cors(Customizer.withDefaults())
                .headers(header -> header.contentSecurityPolicy(csp -> csp.policyDirectives(contentSecurityPolicy)))
                .authorizeHttpRequests(auth -> // auth.requestMatchers("/**").permitAll()
                    auth.requestMatchers("/v2/api-docs",
                            "/swagger-resources/configuration/ui",
                            "/swagger-resources",
                            "/swagger-resources/configuration/security",
                            "/swagger-ui.html",
                            "/webjars/**",
                            HeartBeatController.URL)
                            .permitAll()

                            .requestMatchers("/cancel-auth")
                            .permitAll()

                            .requestMatchers("/jwt/custom-jwt-generate",
                                "/jwt/custom-jwt-userinfo",
                                "/jwt/change-jwt-role")
                            .access(new WebExpressionAuthorizationManager(getAllowedIps()))

                            .requestMatchers("/jwt/**")
                            .permitAll()

                            .requestMatchers("/sessionkey/**")
                            .permitAll()

                            .requestMatchers("/**")
                            .authenticated())
                    // TODO GovSSO RP-initiated logout: when logging out a GovSSO-authenticated session,
                    //  the end_session_endpoint (from the govsso ClientRegistration's discovery metadata)
                    //  should be called with id_token_hint/post_logout_redirect_uri so the GovSSO session
                    //  is also terminated. Not implemented yet - local-only logout for all registrations.
                    // TODO GovSSO back-channel logout: GovSSO can also push a logout_token to a dedicated
                    //  endpoint (POST /oauth2/back-channel-logout/govsso) to end sessions initiated
                    //  elsewhere. Not implemented yet.
                    .logout(logoutUrl ->
                        logoutUrl.logoutUrl("/logout")
                            .logoutSuccessUrl(frontPageRedirectUrl))
                    .addFilterBefore(filter, OAuth2AuthorizationRequestRedirectFilter.class)
                    .oauth2Login(oauth ->
                        oauth.clientRegistrationRepository(clientRegistrationRepository())
                                .loginPage(frontPageRedirectUrl)
                                .redirectionEndpoint(
                                    endpoint -> endpoint.baseUri("/authenticate"))
                            .tokenEndpoint(aot -> aot.accessTokenResponseClient(accessTokenResponseClient))
                            .successHandler(authenticationSuccessHandler));
        return http.build();
    }

    private String getAllowedIps() {
        return Arrays.stream(allowedJWTIps.split(",")).reduce("", (partialString, element) -> {
            if (partialString.equals("")) {
                return partialString + String.format("hasIpAddress('%s')", element);
            }
            return partialString + " or " + String.format("hasIpAddress('%s')", element);
        });
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        return new RestClientAuthorizationCodeTokenResponseClient();
    }


    @Bean
    public JWSSigner rsassaSigner() {

        try {

            return new RSASSASigner(
                    JwtUtils.getJwtSignKeyFromKeystore(
                            jwtSignatureConfig.getKeyStoreType(),
                            jwtSignatureConfig.getKeyStore().getInputStream(),
                            jwtSignatureConfig.getKeyStorePassword().toCharArray(),
                            jwtSignatureConfig.getKeyAlias()));

        } catch (Exception e) {
            log.error("Unable to initialize RSASSASigner ", e);
            throw new IllegalArgumentException("RSASSASigner not initialized, check configuration properties with prefix jwt-integration.signature");
        }
    }

    @Bean
    public JWSVerifier jwsVerifier() {
        try {
            return new RSASSAVerifier(
                    JwtUtils.getJwtSignKeyFromKeystore(
                            jwtSignatureConfig.getKeyStoreType(),
                            jwtSignatureConfig.getKeyStore().getInputStream(),
                            jwtSignatureConfig.getKeyStorePassword().toCharArray(),
                            jwtSignatureConfig.getKeyAlias()));
        } catch (Exception e) {
            log.error("Unable to initialize RSSASSAVerifier", e);
            throw new IllegalArgumentException(e);
        }
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    public static final String REGISTRATION_ID_TARA = "tara";
    public static final String REGISTRATION_ID_GOVSSO = "govsso";

    @Value("${security.oauth2.client.user-authorization-uri}")
    String authorizationUri;
    @Value("${security.oauth2.client.client-id}")
    String clientId;
    @Value("${security.oauth2.client.client-id}")
    String clientName;
    @Value("${security.oauth2.client.client-secret}")
    String clientSecret;
    @Value("${security.oauth2.client.registered-redirect-uri}")
    String redirectUrlTemplate;
    @Value("${security.oauth2.client.access-token-uri}")
    String tokenUri;
    @Value("${security.oauth2.resource.jwk.key-set-uri}")
    String jwkSetUri;
    @Value("${security.oauth2.client.scope}")
    String scope;

    @Value("${security.oauth2.govsso.enabled:false}")
    boolean govssoEnabled;
    @Value("${security.oauth2.govsso.user-authorization-uri:}")
    String govssoAuthorizationUri;
    @Value("${security.oauth2.govsso.client-id:}")
    String govssoClientId;
    @Value("${security.oauth2.govsso.client-secret:}")
    String govssoClientSecret;
    @Value("${security.oauth2.govsso.registered-redirect-uri:}")
    String govssoRedirectUrlTemplate;
    @Value("${security.oauth2.govsso.access-token-uri:}")
    String govssoTokenUri;
    @Value("${security.oauth2.govsso.jwk-set-uri:}")
    String govssoJwkSetUri;
    @Value("${security.oauth2.govsso.scope:openid}")
    String govssoScope;


    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        log.info("SecurityConfiguration.clientRegistrationRepository(): triggered with "
                + authorizationUri
                + redirectUrlTemplate
                + tokenUri);

        List<ClientRegistration> registrations = new ArrayList<>();

        registrations.add(ClientRegistration
                .withRegistrationId(REGISTRATION_ID_TARA)
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

        // GovSSO registration is opt-in (security.oauth2.govsso.enabled=true) so that environments
        // which haven't been onboarded to GovSSO yet keep working with just the tara registration.
        if (govssoEnabled) {
            log.info("SecurityConfiguration.clientRegistrationRepository(): govsso registration enabled");
            registrations.add(ClientRegistration
                    .withRegistrationId(REGISTRATION_ID_GOVSSO)
                    .authorizationUri(govssoAuthorizationUri)
                    .clientId(govssoClientId)
                    .clientName(govssoClientId)
                    .clientSecret(govssoClientSecret)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(govssoRedirectUrlTemplate)
                    .tokenUri(govssoTokenUri)
                    .jwkSetUri(govssoJwkSetUri)
                    .scope(defaultString(govssoScope).split("[\\s]+"))
                    .build());
        }

        return new InMemoryClientRegistrationRepository(registrations);
    }

    // TODO GovSSO token refresh: unlike tara, a GovSSO session can be refreshed via the refresh_token
    //  grant without a full re-authentication round-trip. Not implemented yet - GovSSO sessions expire
    //  the same way tara sessions do today.

}
