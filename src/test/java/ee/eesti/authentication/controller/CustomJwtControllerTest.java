package ee.eesti.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.AbstractSpringBasedTest;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CustomJwtControllerTest extends AbstractSpringBasedTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CustomJwtTokenInfoRepository customJwtTokenInfoRepository;

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

        Cookie cookie = new Cookie("cookieName", jwtTokenString);

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
                .andExpect(status().isBadRequest());
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

        Cookie cookie = new Cookie("cookieName", jwtTokenString);

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
                .andExpect(status().isBadRequest());

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

        Cookie customJwtCookie = new Cookie("cookieName", jwtTokenString);

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
                .andExpect(status().isBadRequest());


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

        Cookie customJwtCookie = new Cookie("cookieName", jwtTokenString);

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

        SignedJWT customJwtToken = SignedJWT.parse(jwtTokenString);
        Cookie customJwtCookie = new Cookie("cookieName", jwtTokenString);

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk());

        String extendedCustomTokenString = mvc.perform(
                        post("/jwt/custom-jwt-extend")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("cookieName"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertNotEquals(jwtTokenString, extendedCustomTokenString);

        UUID customJwtTokenId = UUID.fromString(customJwtToken.getJWTClaimsSet().getJWTID());
        assertTrue(customJwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(customJwtTokenId).isPresent());

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(customJwtCookie)
                                .content("cookieName"))
                .andExpect(status().isBadRequest());

        SignedJWT extendedCustomJwtToken = SignedJWT.parse(extendedCustomTokenString);

        assertThat(customJwtToken.getJWTClaimsSet().getClaims().size(), is(extendedCustomJwtToken.getJWTClaimsSet().getClaims().size()));
        assertThat(customJwtToken.getJWTClaimsSet().getExpirationTime(), lessThanOrEqualTo(extendedCustomJwtToken.getJWTClaimsSet().getExpirationTime()));

        customJwtTokenRequest.getContent().forEach((key, value) -> {
            try {
                assertThat(customJwtToken.getJWTClaimsSet().getClaims(), hasEntry(key, value));
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        });

        mvc.perform(
                        post("/jwt/custom-jwt-verify")
                                .cookie(new Cookie("cookieName", extendedCustomTokenString))
                                .content("cookieName"))
                .andExpect(status().isOk());
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

        Cookie customJwtCookie = new Cookie("cookieName", jwtTokenString);

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
