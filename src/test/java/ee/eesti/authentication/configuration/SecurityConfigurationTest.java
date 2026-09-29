package ee.eesti.authentication.configuration;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import jakarta.servlet.http.HttpSession;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class SecurityConfigurationTest extends AbstractSpringBasedTest {
    private static final String AUTHORIZATION_ENDPOINT = "/oauth2/authorization/tara";

    @Autowired
    private MockMvc mvc;
    //mocked in TestProfileConfiguration
    @Autowired
    private OAuth2AccessTokenResponseClient<?> mockClient;
    //mocked in TestProfileConfiguration
    @Autowired
    private JwtDecoder jwtDecoder;
    @Value("${security.oauth2.client.user-authorization-uri}")
    private String userAuthorizationUri;
    @Value("${security.oauth2.client.client-id}")
    private String clientId;
    @Value("${security.oauth2.govsso.user-authorization-uri}")
    private String govssoUserAuthorizationUri;
    @Value("${frontpage.redirect.url}")
    private String frontPageRedirectUrl;
    @Autowired
    private LegacyPortalIntegrationConfig config;
    @Autowired
    private JwtSignatureConfig signatureConfig;

    @Test
    void testRedirectToLoginForm() throws Exception {
        mvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(frontPageRedirectUrl));
    }

    @Test
    void testRedirectToGovssoAuthorizationEndpoint() throws Exception {
        MvcResult result = mvc.perform(get("/oauth2/authorization/govsso"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirectedUrl = result.getResponse().getRedirectedUrl();
        assertNotNull(redirectedUrl);
        assertTrue(redirectedUrl.startsWith(govssoUserAuthorizationUri));
    }


    @BeforeEach
    void setUp() throws Exception {
        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OidcParameterNames.ID_TOKEN, "ID");
        OAuth2AccessTokenResponse value = OAuth2AccessTokenResponse
                .withToken("test")
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .additionalParameters(additionalParams)
                .build();

        Mockito.when(mockClient.getTokenResponse(Mockito.any())).thenReturn(value);

        HashMap<String, Object> headers = new HashMap<>();
        headers.put("random", "stuff");
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("more", "random stuff");
        claims.put(IdTokenClaimNames.ISS, new URL(userAuthorizationUri));
        claims.put(IdTokenClaimNames.SUB, "EE12345678901");
        claims.put(IdTokenClaimNames.AUD, Collections.singletonList(clientId));
        claims.put("profile_attributes", mockProfileAttributes());
        Jwt jwtValue = new Jwt("test", Instant.now(), Instant.MAX, headers, claims);
        Mockito.when(jwtDecoder.decode(Mockito.anyString())).thenReturn(jwtValue);
    }

    // The real TARA issues an id_token whose "nonce" claim is the hash of the nonce that was sent in the
    // original authorization request; OidcAuthorizationCodeAuthenticationProvider verifies this itself
    // (independently of the mocked JwtDecoder), so the mocked id_token has to include a matching hash
    // for the flow to get past nonce validation.
    private void stubIdTokenForNonce(String nonce) throws Exception {
        HashMap<String, Object> headers = new HashMap<>();
        headers.put("random", "stuff");
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("more", "random stuff");
        claims.put(IdTokenClaimNames.ISS, new URL(userAuthorizationUri));
        claims.put(IdTokenClaimNames.SUB, "EE12345678901");
        claims.put(IdTokenClaimNames.AUD, Collections.singletonList(clientId));
        claims.put("profile_attributes", mockProfileAttributes());
        claims.put("nonce", createNonceHash(nonce));
        Jwt jwtValue = new Jwt("test", Instant.now(), Instant.MAX, headers, claims);
        Mockito.when(jwtDecoder.decode(Mockito.anyString())).thenReturn(jwtValue);
    }

    // AuthenticationSuccessHandler casts the "profile_attributes" claim to (raw) LinkedTreeMap - the type
    // real TARA nested-claim values come back as - so the mocked id_token has to match that shape exactly
    // rather than any generic Map/JSONObject implementation.
    private static LinkedTreeMap<String, Object> mockProfileAttributes() {
        LinkedTreeMap<String, Object> profileAttributes = new LinkedTreeMap<>();
        profileAttributes.put("given_name", "Test");
        profileAttributes.put("family_name", "User");
        return profileAttributes;
    }

    private static String createNonceHash(String nonce) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(nonce.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    // The "nonce" query param sent to the (mocked) authorization endpoint is already the hash - the raw
    // nonce that has to be hashed again for stubIdTokenForNonce() only lives server-side, in the
    // OAuth2AuthorizationRequest that HttpSessionOAuth2AuthorizationRequestRepository stashed in the
    // session during the first (redirect) step.
    private String extractOriginalNonce(TaraAuthTestHelper taraFirstStep) {
        MockHttpServletRequest lookupRequest = new MockHttpServletRequest();
        lookupRequest.setSession((MockHttpSession) taraFirstStep.redirectToTaraMockResult.getRequest().getSession());
        lookupRequest.setParameter("state", taraFirstStep.extractedQueryParams.get("state").get(0));

        OAuth2AuthorizationRequest authorizationRequest = new HttpSessionOAuth2AuthorizationRequestRepository()
                .loadAuthorizationRequest(lookupRequest);
        assertNotNull(authorizationRequest, "authorization request not found in session");
        return authorizationRequest.getAttribute(OidcParameterNames.NONCE);
    }

    //    @Test
//     void testRedirectBackToLegacyPortalWhenRedirectParamIsPresentInTheRequest() throws Exception {
//        String redirectUrl = config.getLegacyUrl();
//        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(redirectUrl, AUTHORIZATION_ENDPOINT);
//
//        assertNotNull(taraFirstStep.redirectToTaraMockResult.getRequest().getSession());
//
//        mvc.perform(get("/authenticate")
//                .session(getMockHttpSession(taraFirstStep.redirectToTaraMockResult.getRequest().getSession()))
//                .param("state", taraFirstStep.extractedQueryParams.get("state").get(0))
//                .param("response_type", taraFirstStep.extractedQueryParams.get("response_type").get(0))
//                .param("scope", taraFirstStep.extractedQueryParams.get("scope").get(0))
//                .param("client_id", taraFirstStep.extractedQueryParams.get("client_id").get(0))
//                .param("redirect_uri", taraFirstStep.extractedQueryParams.get("redirect_uri").get(0))
//                .param("code", "openid"))
//
//                .andExpect(cookie().exists(config.getSessionCookieName()))
//                .andExpect(status().is3xxRedirection())
//                .andExpect(redirectedUrl(redirectUrl))
//        ;
//    }
    @Test
    void testRedirectBackToCallbackUrlIfPresentInTheRequest() throws Exception {
        String redirectUrl = config.getLegacyUrl();
        String expectedRedirectUrl = "https://test.com";
        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(redirectUrl, AUTHORIZATION_ENDPOINT + "?callback_url=".concat(expectedRedirectUrl));

        assertNotNull(taraFirstStep.redirectToTaraMockResult.getRequest().getSession());

        stubIdTokenForNonce(extractOriginalNonce(taraFirstStep));

        mvc.perform(get("/authenticate")
                        .session(getMockHttpSession(taraFirstStep.redirectToTaraMockResult.getRequest().getSession()))
                        .param("state", taraFirstStep.extractedQueryParams.get("state").get(0))
                        .param("response_type", taraFirstStep.extractedQueryParams.get("response_type").get(0))
                        .param("scope", taraFirstStep.extractedQueryParams.get("scope").get(0))
                        .param("client_id", taraFirstStep.extractedQueryParams.get("client_id").get(0))
                        .param("redirect_uri", taraFirstStep.extractedQueryParams.get("redirect_uri").get(0))
                        .param("code", "openid"))

//                .andExpect(cookie().exists(config.getSessionCookieName()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(expectedRedirectUrl))
        ;
    }


    @Test
    void testGetBackJwtTokenWhenNoRedirectParameterIsPresentInTheRequest() throws Exception {
        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(null, AUTHORIZATION_ENDPOINT);

        assertNotNull(taraFirstStep.redirectToTaraMockResult.getRequest().getSession());

        stubIdTokenForNonce(extractOriginalNonce(taraFirstStep));

        mvc.perform(get("/authenticate")
                        .session(getMockHttpSession(taraFirstStep.redirectToTaraMockResult.getRequest().getSession()))
                        .param("state", taraFirstStep.extractedQueryParams.get("state").get(0))
                        .param("response_type", taraFirstStep.extractedQueryParams.get("response_type").get(0))
                        .param("scope", taraFirstStep.extractedQueryParams.get("scope").get(0))
                        .param("client_id", taraFirstStep.extractedQueryParams.get("client_id").get(0))
                        .param("redirect_uri", taraFirstStep.extractedQueryParams.get("redirect_uri").get(0))
                        .param("code", "openid"))

//                .andExpect(cookie().exists(config.getSessionCookieName()))
                .andExpect(status().isOk())
                .andExpect(result -> {
                    SignedJWT signedJWT = SignedJWT.parse(result.getResponse().getContentAsString());
                    assertTrue(signedJWT.verify(new RSASSAVerifier(getRSAKey(signatureConfig))));
                })
        ;
    }

    private TaraAuthTestHelper getTaraFirstAuthStepDone(String redirectUrl, String authorizationUrl) throws Exception {
        //redirect to tara
        MockHttpServletRequestBuilder mockHttpServletRequestBuilder = get(authorizationUrl);
        if (redirectUrl != null) {
            mockHttpServletRequestBuilder.header("Referer", config.getLegacyPortalRefererMarker());
        }

        MvcResult redirectToTaraMockResult = mvc
                .perform(mockHttpServletRequestBuilder)
                .andExpect(status().is3xxRedirection())
                .andReturn();

        //fake tara reports back a token
        String redirectedUrl = redirectToTaraMockResult.getResponse().getRedirectedUrl();

        assertNotNull(redirectedUrl);

        Map<String, List<String>> stringListMap = extractQueryParams(redirectedUrl.substring(redirectedUrl.lastIndexOf('?') + 1));

        return new TaraAuthTestHelper(redirectToTaraMockResult, stringListMap);
    }

    private MockHttpSession getMockHttpSession(HttpSession session) {
        MockHttpSession mockSession = new MockHttpSession(session.getServletContext(), session.getId());
        Enumeration<String> attributeNames = session.getAttributeNames();


        while (attributeNames.hasMoreElements()) {
            String attributeName = attributeNames.nextElement();
            mockSession.setAttribute(attributeName, session.getAttribute(attributeName));
        }

        return mockSession;
    }

    private Map<String, List<String>> extractQueryParams(String query) {
        return Arrays.stream(query.split("&"))
                .map(this::splitQueryParameter)
                .collect(Collectors.groupingBy(AbstractMap.SimpleImmutableEntry::getKey, LinkedHashMap::new, mapping(Map.Entry::getValue, toList())));
    }

    private AbstractMap.SimpleImmutableEntry<String, String> splitQueryParameter(String it) {

        try {
            it = URLDecoder.decode(it, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        final int idx = it.indexOf("=");
        final String key = idx > 0 ? it.substring(0, idx) : it;
        final String value = idx > 0 && it.length() > idx + 1 ? it.substring(idx + 1) : null;

        return new AbstractMap.SimpleImmutableEntry<>(key, value);
    }

    private static class TaraAuthTestHelper {
        final MvcResult redirectToTaraMockResult;
        final Map<String, List<String>> extractedQueryParams;

        TaraAuthTestHelper(MvcResult redirectToTaraMockResult, Map<String, List<String>> extractedQueryParams) {
            this.redirectToTaraMockResult = redirectToTaraMockResult;
            this.extractedQueryParams = extractedQueryParams;
        }
    }

    public static RSAKey getRSAKey(JwtSignatureConfig signatureConfig) throws Exception {
        KeyStore signKeyStore = KeyStore.getInstance(signatureConfig.getKeyStoreType());
        signKeyStore.load(signatureConfig.getKeyStore().getInputStream(), signatureConfig.getKeyStorePassword().toCharArray());

        JWKSet jwkSet = JWKSet.load(signKeyStore, name -> signatureConfig.getKeyStorePassword().toCharArray());
        JWK signKey = jwkSet.getKeyByKeyId(signatureConfig.getKeyAlias());

        return (RSAKey) signKey;
    }

}
