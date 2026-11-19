package ee.eesti.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.domain.CustomJwtTokenRequest;
import ee.eesti.authentication.repository.CustomJwtTokenInfoRepository;
import org.json.JSONObject;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import jakarta.servlet.http.Cookie;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CustomJwtControllerTest extends AbstractSpringBasedTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CustomJwtTokenInfoRepository customJwtTokenInfoRepository;

    @Autowired
    private JwtSignatureConfig jwtSignatureConfig;

    private final String customJwtControllerGenerateEndpoint = "/jwt/custom-jwt-generate";

    @Test
    void testCustomJwtTokenCreated() throws Exception {

        CustomJwtTokenRequest jwtTokenRequest = getValidCustomJwtTokenRequest(42);

        //Valid Token
        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(jwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("cookieName"))
                .andExpect(cookie().httpOnly("cookieName", true))
                .andExpect(cookie().secure("cookieName", true))
                .andReturn().getResponse().getContentAsString();

        System.out.println(jwtTokenString);
    }

    @Test
    void testCustomJwtSidClaimIsStored() throws Exception {
        CustomJwtTokenRequest jwtTokenRequest = getValidCustomJwtTokenRequest(42);
        jwtTokenRequest.getContent().put("sid", "custom-sid-1");

        String body = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(jwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        UUID jwtId = UUID.fromString(SignedJWT.parse(extractToken(body)).getJWTClaimsSet().getJWTID());
        assertEquals("custom-sid-1", customJwtTokenInfoRepository.findById(jwtId).orElseThrow().getSid());
    }

    // jwt-integration.signature.sid-claim decides which content key is stored as the session id
    @Test
    void testCustomJwtSidClaimNameIsConfigurable() throws Exception {
        String originalSidClaim = jwtSignatureConfig.getSidClaim();
        jwtSignatureConfig.setSidClaim("session_id");
        try {
            CustomJwtTokenRequest configuredName = getValidCustomJwtTokenRequest(42);
            configuredName.getContent().put("session_id", "configured-sid");
            String token = generateCustomJwt(configuredName);
            UUID jwtId = UUID.fromString(SignedJWT.parse(token).getJWTClaimsSet().getJWTID());
            assertEquals("configured-sid", customJwtTokenInfoRepository.findById(jwtId).orElseThrow().getSid());

            CustomJwtTokenRequest defaultName = getValidCustomJwtTokenRequest(42);
            defaultName.getContent().put("sid", "ignored-sid");
            String otherToken = generateCustomJwt(defaultName);
            UUID otherJwtId = UUID.fromString(SignedJWT.parse(otherToken).getJWTClaimsSet().getJWTID());
            assertNull(customJwtTokenInfoRepository.findById(otherJwtId).orElseThrow().getSid());

            mvc.perform(post("/jwt/custom-jwt-update-required-sid").content("configured-sid"))
                    .andExpect(status().isOk())
                    .andExpect(content().json("{\"updateRequired\": 1}"));
            verifyCustomJwt(token, status().isForbidden());
        } finally {
            jwtSignatureConfig.setSidClaim(originalSidClaim);
        }
    }

    @Test
    void testBlacklistBySidInvalidatesCustomJwt() throws Exception {
        CustomJwtTokenRequest jwtTokenRequest = getValidCustomJwtTokenRequest(42);
        jwtTokenRequest.getContent().put("sid", "custom-sid-e2e");

        String token = extractToken(mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(jwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        mvc.perform(post("/jwt/custom-jwt-verify").content("cookieName").cookie(new Cookie("cookieName", token)))
                .andExpect(status().isOk());

        mvc.perform(post("/jwt/blacklist-sid").content("custom-sid-e2e"))
                .andExpect(status().isOk());

        mvc.perform(post("/jwt/custom-jwt-verify").content("cookieName").cookie(new Cookie("cookieName", token)))
                .andExpect(status().isUnauthorized());
    }

    // /jwt/custom-jwt-generate (and /jwt/custom-jwt-extend, which delegates to it) wrap the signed JWT
    // in a {"token": "<jwt>"} JSON body (since 785fd84, "Formated Generate Response") rather than
    // returning the bare JWT string.
    private String extractToken(String generateResponseBody) throws Exception {
        return objectMapper.readTree(generateResponseBody).get("token").asText();
    }

    private CustomJwtTokenRequest getValidCustomJwtTokenRequest(int expirationInMinutes) {
        Map<String, Object> stringObjectMap = new HashMap<>();
        stringObjectMap.put("testContent", "some test here");
        stringObjectMap.put("testContent1", "some more test content here");
        stringObjectMap.put("testContent2", "some different content here test here");
        stringObjectMap.put("testNumber", 42L);
        Map<String, Object> hashMap = new HashMap<>();
        hashMap.put("innerKey", "innerValue");
        stringObjectMap.put("objectTest", hashMap);
        return CustomJwtTokenRequest
                .builder()
                .jwtName("cookieName")
                .content(stringObjectMap)
                .expirationInMinutes(expirationInMinutes)
                .build();
    }

    // Stays disabled: RestExceptionHandler catches Throwable globally (including the
    // MethodArgumentNotValidException / NullPointerException these cases trigger) and always returns
    // HTTP 200, so @Valid violations on CustomJwtTokenRequest can never actually surface as 400 today.
    // That's a main-code behavior issue, not a stale assertion, so left disabled rather than "fixed" by
    // asserting the current (200) behavior as if it were correct.
    @Test
    @Disabled
    void testCustomJwtTokenValidation() throws Exception {
        {
            //no Cookie name
            Map<String, Object> stringObjectMap = new HashMap<>();
            stringObjectMap.put("testContent", "some test here");
            stringObjectMap.put("testContent1", "some test here");
            stringObjectMap.put("testContent2", "some test here");
            CustomJwtTokenRequest jwtTokenRequest = CustomJwtTokenRequest
                    .builder()
                    .content(stringObjectMap)
                    .expirationInMinutes(42)
                    .build();

            mvc.perform(
                            post(customJwtControllerGenerateEndpoint)
                                    .content(objectMapper.writeValueAsString(jwtTokenRequest))
                                    .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isBadRequest());
        }
        {
            //expiration is negative
            Map<String, Object> stringObjectMap = new HashMap<>();
            stringObjectMap.put("testContent", "some test here");
            stringObjectMap.put("testContent1", "some test here");
            stringObjectMap.put("testContent2", "some test here");
            CustomJwtTokenRequest jwtTokenRequest = CustomJwtTokenRequest
                    .builder()
                    .jwtName("testCookieName")
                    .content(stringObjectMap)
                    .expirationInMinutes(-42)
                    .build();

            mvc.perform(
                            post(customJwtControllerGenerateEndpoint)
                                    .content(objectMapper.writeValueAsString(jwtTokenRequest))
                                    .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isBadRequest());
        }
        {
            //empty content Map should be OK
            CustomJwtTokenRequest jwtTokenRequest = CustomJwtTokenRequest
                    .builder()
                    .jwtName("testCookieName")
                    .expirationInMinutes(12)
                    .build();

            mvc.perform(
                            post(customJwtControllerGenerateEndpoint)
                                    .content(objectMapper.writeValueAsString(jwtTokenRequest))
                                    .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(cookie().exists("testCookieName"))
            ;
        }

    }


    @Test
    void testVerifyCustomJwtTokenGreenFlow() throws Exception {

        CustomJwtTokenRequest jwtTokenRequest = getValidCustomJwtTokenRequest(1);

        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(jwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Cookie cookie = new Cookie("cookieName", extractToken(jwtTokenString));

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(cookie)
                                .content("cookieName"))
                .andExpect(status().isOk());
    }

    @Test
    void testVerifyCustomJwtTokenExpiredToken() throws Exception {

        String jwtTokenExpiredLongTimeAgo = "eyJhbGciOiJSUzI1NiJ9." +
                                            "eyJzdWIiOiIiLCJ0ZXN0Q29udGVudCI6InNvbWUgdGVzdCBoZXJlIiwiaXNzIjoiZWVzdGkuZWUiLCJ0ZXN0Q29udGVudDIiOiJzb21lIHRlc3QgaGVyZSIsInRlc3RDb250ZW50MSI6InNvbWUgdGVzdCBoZXJlIiwiZXhwIjoxNTU5MTQ2OTYzLCJpYXQiOjE1NTkxNDY5NjIsImp0aSI6IjFlNmI3Yzk5LTgwM2EtNDBlNS04OWNkLTBhMTU2ODBmYzVjZSJ9." +
                                            "aEGQ829DBW4K9Fg_9dDkyfzyLY5rZM1O0o2sMKNcduxsTA-F9YWmsYaOBuYrtNKPcq_fPmLex_VU6SD9-wNWSPNOj9650DFeJ0-T6lmd8GqfUlOoD0-DX2kJvrzFaVU9nJCXlNWlw5R0aY9Zxdmg49HBl-LJriA1BOCWjIhebNEAQvJnUk77zOMn5bRRi2_slLyCR8__ItPsPgKKjl1I9jDJ6jDawr3UhiOiAVo5U7GHlqTPv9gveKTrsO4uFF_Z5KGUJ1xs9xH5jYUny-vzR3A_LizPOCWSvBcDzQMTU48YavssMXBZOIiO0ahE9kuj8CxxPnMMTgo2LcT1zUMwTA";

        Cookie cookie = new Cookie("cookieName", jwtTokenExpiredLongTimeAgo);

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(cookie)
                                .content("cookieName"))
                .andExpect(status().isUnauthorized());
    }


    @Test
    void testVerifyCustomJwtTokenEmptyCookieNameOrNoCookie() throws Exception {

        CustomJwtTokenRequest jwtTokenRequest = getValidCustomJwtTokenRequest(42);

        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(jwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Cookie cookie = new Cookie("cookieName", extractToken(jwtTokenString));

        // no param
        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(cookie))
                .andExpect(status().isBadRequest());

        // cookie not set
        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .content("cookieName")
                )
                .andExpect(status().isUnauthorized());

    }

    @Test
    void testCustomJwtTokenBlacklisting() throws Exception {

        CustomJwtTokenRequest customJwtTokenRequest = getValidCustomJwtTokenRequest(42);

        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(customJwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Cookie customJwtCookie = new Cookie("cookieName", extractToken(jwtTokenString));

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk());

        mvc.perform(
                        post("/jwt/custom-jwt-blacklist")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk());

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isUnauthorized());


        SignedJWT jwt = SignedJWT.parse(customJwtCookie.getValue());

        assertTrue(customJwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(UUID.fromString(jwt.getJWTClaimsSet().getJWTID())).isPresent());
    }

    @Test
    void testCustomJwtTokenBlacklistingValidation() throws Exception {
        CustomJwtTokenRequest customJwtTokenRequest = getValidCustomJwtTokenRequest(42);

        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(customJwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Cookie customJwtCookie = new Cookie("cookieName", extractToken(jwtTokenString));

        mvc.perform(
                        post("/jwt/custom-jwt-blacklist")
                                .cookie(customJwtCookie)
                                .content("cookieName1"))
                .andExpect(status().isOk());

        mvc.perform(
                        post("/jwt/custom-jwt-blacklist")
                                .content("cookieName"))
                .andExpect(status().isOk());

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk());

        SignedJWT jwt = SignedJWT.parse(customJwtCookie.getValue());

        assertFalse(customJwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(UUID.fromString(jwt.getJWTClaimsSet().getJWTID())).isPresent());
    }

    @Test
    void testCustomJwtTokenExtension() throws Exception {
        CustomJwtTokenRequest customJwtTokenRequest = getValidCustomJwtTokenRequest(42);

        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(customJwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        SignedJWT customJwtToken = SignedJWT.parse(extractToken(jwtTokenString));
        Cookie customJwtCookie = new Cookie("cookieName", extractToken(jwtTokenString));

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk());

        CustomJwtTokenRequest extendRequest = getValidCustomJwtTokenRequest(60);
        extendRequest.getContent().put("testContent", "updated content");
        extendRequest.getContent().put("addedOnExtend", "new claim");
        extendRequest.getContent().remove("testContent1");

        String extendedCustomTokenString = mvc.perform(
                        post("/jwt/custom-jwt-extend")
                                .cookie(customJwtCookie)
                                .content(objectMapper.writeValueAsString(extendRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("cookieName"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertNotEquals(extractToken(jwtTokenString), extractToken(extendedCustomTokenString));

        UUID customJwtTokenId = UUID.fromString(customJwtToken.getJWTClaimsSet().getJWTID());
        assertTrue(customJwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(customJwtTokenId).isPresent());

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isUnauthorized());

        SignedJWT extendedCustomJwtToken = SignedJWT.parse(extractToken(extendedCustomTokenString));

        assertThat(customJwtToken.getJWTClaimsSet().getClaims().size(), is(extendedCustomJwtToken.getJWTClaimsSet().getClaims().size()));
        assertThat(customJwtToken.getJWTClaimsSet().getExpirationTime(), lessThanOrEqualTo(extendedCustomJwtToken.getJWTClaimsSet().getExpirationTime()));

        // the extended token carries the content from the extend request body, not the old token's claims
        Map<String, Object> extendedClaims = extendedCustomJwtToken.getJWTClaimsSet().getClaims();
        assertThat(extendedClaims, hasEntry("testContent", "updated content"));
        assertThat(extendedClaims, hasEntry("addedOnExtend", "new claim"));
        assertFalse(extendedClaims.containsKey("testContent1"));
        long lifetimeMillis = extendedCustomJwtToken.getJWTClaimsSet().getExpirationTime().getTime()
                - extendedCustomJwtToken.getJWTClaimsSet().getIssueTime().getTime();
        assertEquals(60 * 60_000L, lifetimeMillis, 1_000L);

        customJwtTokenRequest.getContent().forEach((key, value) -> {
            try {
                assertThat(customJwtToken.getJWTClaimsSet().getClaims(), hasEntry(key, value));
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        });

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(new Cookie("cookieName", extractToken(extendedCustomTokenString)))
                                .content("cookieName"))
                .andExpect(status().isOk());
    }

    // Legacy format: plain-text cookie name as body - claims and original lifetime are carried over.
    @Test
    void testCustomJwtTokenExtensionWithPlainTextCookieName() throws Exception {
        CustomJwtTokenRequest customJwtTokenRequest = getValidCustomJwtTokenRequest(42);

        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(customJwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        SignedJWT customJwtToken = SignedJWT.parse(extractToken(jwtTokenString));
        Cookie customJwtCookie = new Cookie("cookieName", extractToken(jwtTokenString));

        String extendedCustomTokenString = mvc.perform(
                        post("/jwt/custom-jwt-extend")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("cookieName"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertNotEquals(extractToken(jwtTokenString), extractToken(extendedCustomTokenString));

        UUID customJwtTokenId = UUID.fromString(customJwtToken.getJWTClaimsSet().getJWTID());
        assertTrue(customJwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(customJwtTokenId).isPresent());

        SignedJWT extendedCustomJwtToken = SignedJWT.parse(extractToken(extendedCustomTokenString));
        Map<String, Object> extendedClaims = extendedCustomJwtToken.getJWTClaimsSet().getClaims();

        assertThat(customJwtToken.getJWTClaimsSet().getClaims().size(), is(extendedClaims.size()));
        assertThat(customJwtToken.getJWTClaimsSet().getExpirationTime(), lessThanOrEqualTo(extendedCustomJwtToken.getJWTClaimsSet().getExpirationTime()));
        customJwtTokenRequest.getContent().forEach((key, value) -> assertThat(extendedClaims, hasEntry(key, value)));
        long lifetimeMillis = extendedCustomJwtToken.getJWTClaimsSet().getExpirationTime().getTime()
                - extendedCustomJwtToken.getJWTClaimsSet().getIssueTime().getTime();
        assertEquals(42 * 60_000L, lifetimeMillis, 1_000L);

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(new Cookie("cookieName", extractToken(extendedCustomTokenString)))
                                .content("cookieName"))
                .andExpect(status().isOk());
    }

    // JSON body without JWTName is rejected up front: no new token, old token stays valid.
    @Test
    void testCustomJwtTokenExtensionWithInvalidJsonBodyDoesNothing() throws Exception {
        CustomJwtTokenRequest customJwtTokenRequest = getValidCustomJwtTokenRequest(42);

        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(customJwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Cookie customJwtCookie = new Cookie("cookieName", extractToken(jwtTokenString));
        CustomJwtTokenRequest invalidRequest = getValidCustomJwtTokenRequest(60);
        invalidRequest.setJwtName(null);

        mvc.perform(
                        post("/jwt/custom-jwt-extend")
                                .cookie(customJwtCookie)
                                .content(objectMapper.writeValueAsString(invalidRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(cookie().doesNotExist("cookieName"))
                .andExpect(content().string(""));

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk());
    }

    private String generateCustomJwt(CustomJwtTokenRequest request) throws Exception {
        return extractToken(mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(request))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private void verifyCustomJwt(String token, org.springframework.test.web.servlet.ResultMatcher expectedStatus) throws Exception {
        mvc.perform(post("/jwt/custom-jwt-verify").content("cookieName").cookie(new Cookie("cookieName", token)))
                .andExpect(expectedStatus);
    }

    // greylisted token: verify -> 403, userinfo shows the flag, JSON extend issues a clean token, old one -> 401
    @Test
    void testCustomJwtTokenUpdateRequiredByCookie() throws Exception {
        String token = generateCustomJwt(getValidCustomJwtTokenRequest(42));
        Cookie cookie = new Cookie("cookieName", token);

        verifyCustomJwt(token, status().isOk());

        mvc.perform(post("/jwt/custom-jwt-update-required").content("cookieName").cookie(cookie))
                .andExpect(status().isOk());

        verifyCustomJwt(token, status().isForbidden());

        String userInfo = mvc.perform(post("/jwt/custom-jwt-userinfo").content("cookieName").cookie(cookie))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertTrue(new JSONObject(userInfo).getBoolean("JWTUpdateRequired"));

        CustomJwtTokenRequest updated = getValidCustomJwtTokenRequest(42);
        updated.getContent().put("testContent", "fresh");
        String newToken = extractToken(mvc.perform(
                        post("/jwt/custom-jwt-extend")
                                .cookie(cookie)
                                .content(objectMapper.writeValueAsString(updated))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        verifyCustomJwt(newToken, status().isOk());
        verifyCustomJwt(token, status().isUnauthorized());

        String newUserInfo = mvc.perform(post("/jwt/custom-jwt-userinfo").content("cookieName").cookie(new Cookie("cookieName", newToken)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertFalse(new JSONObject(newUserInfo).getBoolean("JWTUpdateRequired"));
    }

    // greylisting by sid only hits that sid's tokens; legacy (plain-text) extend keeps the flag
    @Test
    void testCustomJwtTokenUpdateRequiredBySid() throws Exception {
        CustomJwtTokenRequest withSid = getValidCustomJwtTokenRequest(42);
        withSid.getContent().put("sid", "greylist-sid");
        String token = generateCustomJwt(withSid);

        CustomJwtTokenRequest otherSid = getValidCustomJwtTokenRequest(42);
        otherSid.getContent().put("sid", "other-sid");
        String otherToken = generateCustomJwt(otherSid);

        mvc.perform(post("/jwt/custom-jwt-update-required-sid").content("greylist-sid"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"updateRequired\": 1}"));

        verifyCustomJwt(token, status().isForbidden());
        verifyCustomJwt(otherToken, status().isOk());

        String legacyExtended = extractToken(mvc.perform(
                        post("/jwt/custom-jwt-extend")
                                .cookie(new Cookie("cookieName", token))
                                .content("cookieName"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        verifyCustomJwt(legacyExtended, status().isForbidden());
        verifyCustomJwt(token, status().isUnauthorized());

        mvc.perform(post("/jwt/custom-jwt-update-required-sid"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testCustomJwtTokenUserinfo() throws Exception {
        CustomJwtTokenRequest customJwtTokenRequest = getValidCustomJwtTokenRequest(42);

        String jwtTokenString = mvc.perform(
                        post(customJwtControllerGenerateEndpoint)
                                .content(objectMapper.writeValueAsString(customJwtTokenRequest))
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Cookie customJwtCookie = new Cookie("cookieName", extractToken(jwtTokenString));

        String customUserInfoResponse = mvc.perform(
                        post("/jwt/custom-jwt-userinfo")
                                .content("cookieName")
                                .cookie(customJwtCookie)
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();


        JSONObject jsonObject = new JSONObject(customUserInfoResponse);

        assertNotNull(jsonObject);

        assertThat(jsonObject.get("testContent"), is("some test here"));
        assertThat(jsonObject.get("testContent1"), is("some more test content here"));
        assertThat(jsonObject.get("testContent2"), is("some different content here test here"));
        assertThat(jsonObject.get("testNumber"), is(42));
        JSONObject objectTest = (JSONObject) jsonObject.get("objectTest");

        assertNotNull(objectTest);
        assertThat(objectTest.get("innerKey"), is("innerValue"));

        //blacklisting
        mvc.perform(
                        post("/jwt/custom-jwt-blacklist")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk());

        // should not be valid anymore
        mvc.perform(
                        post("/jwt/custom-jwt-userinfo")
                                .content("cookieName")
                                .cookie(customJwtCookie)
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        // invalid cookie name in the request
        mvc.perform(
                        post("/jwt/custom-jwt-userinfo")
                                .content("cookieName1")
                                .cookie(customJwtCookie)
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        // no cookie set
        mvc.perform(
                        post("/jwt/custom-jwt-userinfo")
                                .content("cookieName1")
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        // no cookie set, no request param
        mvc.perform(
                        post("/jwt/custom-jwt-userinfo")
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());

    }
}
