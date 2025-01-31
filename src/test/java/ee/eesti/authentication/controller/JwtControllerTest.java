package ee.eesti.authentication.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.configuration.SecurityConfigurationTest;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import ee.eesti.authentication.service.JwtTokenInfoService;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import jakarta.servlet.http.Cookie;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


class JwtControllerTest extends AbstractSpringBasedTest {

    private static final String DEFAULT_SESSION_ID_1 = "q6pzhtnlb0vppk2s1kj8jbz6rw003tvb";
    private static final String DEFAULT_SESSION_ID_2 = "q6pzhtnlb0vppk2s1kj8jbz6rw003tvc";
    private static final UUID DEFAULT_JWT_TOKEN = UUID.randomUUID();

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JwtSignatureConfig jwtSignatureConfig;

    @Autowired
    private LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;

    @Autowired
    private JWSSigner jwsSigner;

    @Autowired
    private JwtTokenInfoService jwtTokenInfoService;

    @Autowired
    private JwtTokenInfoRepository jwtTokenInfoRepository;

    @Autowired
    private SessionsRepository sessionsRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Value("${role.restrictions.cookie.name:ROLE_RESTRICTIONS}")
    private String roleRestrictionsCookieName;

    @Value("${role.restrictions.cookie.attr:role_restrictions}")
    private String roleRestrctionsAttr;

    @BeforeEach
    void init() {
        jwtTokenInfoRepository.deleteAll();
    }

    @Test
    void testPublicKeyDownload() throws Exception {

        RSAKey rsaKey = SecurityConfigurationTest.getRSAKey(jwtSignatureConfig);
        PublicKey Key = rsaKey.toPublicKey();

        mvc.perform(get("/jwt/verification-key"))
                .andExpect(status().isOk())
                .andExpect(result -> {
                    String keyString = result.getResponse().getContentAsString();
                    System.out.println(keyString);

                    keyString = keyString.replace("-----BEGIN PUBLIC KEY-----\n", "");
                    keyString = keyString.replace("-----END PUBLIC KEY-----", "");

                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decode(keyString));
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey obtainedThroughWeb = keyFactory.generatePublic(pubKeySpec);
                    assertThat(obtainedThroughWeb, is(Key));

                })
        ;
    }

    @Test
    void testUserinfoEndpoint() throws Exception {

        String personalCode = "12345678901";
        String firstName = "John";
        String lastName = "Doe";
        String authMethod = "eIDAS";

        Map<String, String> claimSetToAdd = new HashMap<>();
        claimSetToAdd.put("personalCode", personalCode);
        claimSetToAdd.put("firstName", firstName);
        claimSetToAdd.put("lastName", lastName);
        claimSetToAdd.put("authMethod", authMethod);

        //Valid token info
        Date issueTime = DateUtils.truncate(new Date(), Calendar.SECOND);
        Date expirationDate = DateUtils.addMinutes(issueTime, 30);

        mvc.perform(
                        get("/jwt/userinfo")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), getJwtTokenString(issueTime, expirationDate, jwtUtils.getFirstIssuer(), UUID.randomUUID().toString(), claimSetToAdd, personalCode))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("personalCode", is(personalCode)))
                .andExpect(jsonPath("firstName", is(firstName)))
                .andExpect(jsonPath("lastName", is(lastName)))
                .andExpect(jsonPath("loggedInDate", is(issueTime.getTime())))
                .andExpect(jsonPath("loginExpireDate", is(expirationDate.getTime())))
                .andExpect(jsonPath("authMethod", is(authMethod)))
        ;

        //no cookie
        mvc.perform(
                        get("/jwt/userinfo"))
                .andExpect(status().isBadRequest())
        ;

        //not parsable cookie
        mvc.perform(
                        get("/jwt/userinfo")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), "some random string")))
                .andExpect(status().isBadRequest())
        ;

    }

    @Test
    void testVerificationProcess() throws Exception {

        String personalCode = "11223344551";

        //Valid Token
        mvc.perform(
                        post("/jwt/verify")
                                .content(getJwtTokenString(new Date(), DateUtils.addMinutes(new Date(), 30), jwtUtils.getFirstIssuer(), UUID.randomUUID().toString(), null, personalCode)))
                .andExpect(status().isOk());

        //invalid token
        mvc.perform(
                        post("/jwt/verify")
                                .content("garbage here"))
                .andExpect(status().isBadRequest());

        //Expired token
        mvc.perform(
                        post("/jwt/verify")
                                .content(getJwtTokenString(new Date(), new Date(), jwtUtils.getFirstIssuer(), UUID.randomUUID().toString(), null, personalCode)))
                .andExpect(status().isBadRequest());

        //Invalid issuer
        mvc.perform(
                        post("/jwt/verify")
                                .content(getJwtTokenString(new Date(), new Date(), "not a real issuer thing", UUID.randomUUID().toString(), null, personalCode)))
                .andExpect(status().isBadRequest());

    }

    private String getJwtTokenString(Date issueTime, Date expirationDate, String issuer, String jwtId, Map<String, String> claimSetToAdd, String personalCode) throws JOSEException {
        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder()
                .subject(personalCode)
                .expirationTime(expirationDate)
                .jwtID(jwtId)
                .issueTime(issueTime)
                .issuer(issuer);

        if (claimSetToAdd != null) {
            claimSetToAdd.forEach(claimSetBuilder::claim);
        }

        JWTClaimsSet claimsSet = claimSetBuilder.build();


        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(jwsSigner);

        return signedJWT.serialize();
    }

//    @Test
//    @Transactional
//     void testBlacklistUsingJwtToken() throws Exception {
//
//        //blacklisting using cookie
//
//        JwtTokenInfo jwtTokenInfo = jwtTokenInfoService.createJwtTokenInfo(UUID.randomUUID(), "q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3", new Timestamp(new Date().getTime() + 1000 * 60 * 30));
//        UUID jwtToken = jwtTokenInfo.getJwtUuid();
//        String tokenBlacklistedByUuid = getJwtTokenString(new Date(), DateUtils.addMinutes(new Date(), 10), jwtSignatureConfig.getIssuer(), jwtToken.toString(), null, "11223344556");
//
//
//        //blacklisting using post method
//        mvc.perform(
//                post("/jwt/blacklist")
//                        .cookie(
//                                new Cookie(
//                                        jwtSignatureConfig.getCookieName(),
//                                        tokenBlacklistedByUuid)))
//                .andExpect(status().isOk());
//
//        //same token should not pass verification aftrer blacklisting
//        mvc.perform(post("/jwt/verify")
//                .content(tokenBlacklistedByUuid))
//                .andExpect(status().isBadRequest());
//
//
//        jwtTokenInfo = jwtTokenInfoService.createJwtTokenInfo(DEFAULT_JWT_TOKEN, DEFAULT_SESSION_ID_1, new Timestamp(new Date().getTime() + 1000 * 60 * 30));
//        jwtToken = jwtTokenInfo.getJwtUuid();
//        tokenBlacklistedByUuid = getJwtTokenString(new Date(), DateUtils.addMinutes(new Date(), 10), jwtSignatureConfig.getIssuer(), jwtToken.toString(), null, "11223344556");
//
//        //blacklisting using post method
//        mvc.perform(
//                post("/jwt/blacklist")
//                        .param("jwt", jwtToken.toString()))
//                .andExpect(status().isOk());
//
//        //same token should not pass verification aftrer blacklisting
//        mvc.perform(post("/jwt/verify")
//                .content(tokenBlacklistedByUuid))
//                .andExpect(status().isBadRequest());
//
//        UUID jwtTokenUuid = UUID.randomUUID();
//
//        jwtTokenInfo = jwtTokenInfoService.createJwtTokenInfo(jwtTokenUuid, DEFAULT_SESSION_ID_2, new Timestamp(new Date().getTime() + 1000 * 60 * 30));
//        sessionsRepository.save(
//                createSessionsEntity(
//                        jwtTokenInfo.getLegacySessionId(),
//                        LocalDateTime.now().plusMinutes(42L),
//                        LocalDateTime.now().plusMinutes(42L)));
//
//        String sessionId = jwtTokenInfo.getLegacySessionId();
//
//        mvc.perform(
//                post("/jwt/blacklist")
//                        .param("sessionId", sessionId)
//                        .cookie(new Cookie("PHPSESSID", null)))
//                .andExpect(status().isOk())
//                .andExpect(cookie().maxAge(legacyPortalIntegrationConfig.getSessionCookieName(), 0));
//
//        //blacklisted legacy sessionId should have the validToDate in the past
//
//        SessionsEntity expiredSessionsEnity = sessionsRepository
//                .findBySessionId(sessionId)
//                .orElseThrow(IllegalArgumentException::new);
//
//        assertTrue(expiredSessionsEnity.getValidTo().isBefore(LocalDateTime.now()));
//
//        String tokenBlacklistedBySessionId = getJwtTokenString(new Date(), DateUtils.addMinutes(new Date(), 10), jwtSignatureConfig.getIssuer(), jwtTokenUuid.toString(), null, "11223344556");
//
//        //same token should not pass verification aftrer blacklisting
//        mvc.perform(post("/jwt/verify")
//                .content(tokenBlacklistedBySessionId))
//                .andExpect(status().isBadRequest());
//    }

    @Test
    void testSessionExtensionUsingLegacySessionCookie() throws Exception {

        LocalDateTime creationTime = LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS);
        LocalDateTime legacySessionExpirationDateTime = creationTime.plusMinutes(1L);
        String legacySessionId = "legacySessionId";
        SessionsEntity sessionsEntity = sessionsRepository.saveAndFlush(
                createSessionsEntity(legacySessionId,
                        creationTime,
                        legacySessionExpirationDateTime));
        LocalDateTime expectedExpirationDate = creationTime.plusMinutes(legacyPortalIntegrationConfig.getSessionTimeoutMinutes());

        MvcResult mvcResult = mvc.perform(get("/jwt/extend-jwt-session")
                        .cookie(new Cookie(legacyPortalIntegrationConfig.getSessionCookieName(), sessionsEntity.getSessionId())))
                .andExpect(status().isOk())
                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(notNullValue())))
                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), is(-1)))
                .andExpect(cookie().value(legacyPortalIntegrationConfig.getSessionCookieName(), is(notNullValue())))
                .andExpect(cookie().maxAge(legacyPortalIntegrationConfig.getSessionCookieName(), is(-1)))
                .andReturn();

        Cookie extendedSessionInfo = mvcResult.getResponse().getCookie(jwtSignatureConfig.getCookieName());
        UserInfo userInfo = jwtUtils.decodeJwtTokenFromCookie(extendedSessionInfo);
        assertThat(userInfo.getLoginExpireDate().getTime(), is(greaterThanOrEqualTo(convertToDate(expectedExpirationDate).getTime())));

        SessionsEntity updatedLegacySession = sessionsRepository.findBySessionId(sessionsEntity.getSessionId()).orElseThrow(IllegalStateException::new);

        assertThat(updatedLegacySession.getValidTo().atZone(ZoneId.systemDefault()).toEpochSecond(), is(greaterThanOrEqualTo(expectedExpirationDate.atZone(ZoneId.systemDefault()).toEpochSecond())));

        mvc.perform(
                        get("/jwt/userinfo")
                                .cookie(extendedSessionInfo))
                .andExpect(status().isOk())
                .andExpect(jsonPath("loggedInDate", is(creationTime.atZone(ZoneId.systemDefault()).toInstant().getEpochSecond() * 1000L)))
                .andExpect(jsonPath("loginExpireDate", greaterThanOrEqualTo(expectedExpirationDate.atZone(ZoneId.systemDefault()).toInstant().getEpochSecond() * 1000L)));
    }

//    @Test
//     void testSessionExtensionUsingJwtCookieForEstonianPersonalCode() throws Exception {
//
//        Calendar instance = Calendar.getInstance();
//        instance.set(Calendar.MILLISECOND, 0);
//        Date tokenCreationDate = instance.getTime();
//        instance.add(Calendar.MINUTE, 1);
//        Date oldExpirationDate = instance.getTime();
//        instance.add(Calendar.MINUTE, legacyPortalIntegrationConfig.getSessionTimeoutMinutes());
//
//        UUID oldJwtId = UUID.randomUUID();
//        String personalCode = "EE11223344556";
//        String jwtTokenString = getJwtTokenString(
//                tokenCreationDate,
//                oldExpirationDate, jwtSignatureConfig.getIssuer(), oldJwtId.toString(), Collections.singletonMap("personalCode", personalCode), personalCode);
//
//        jwtTokenInfoRepository.save(new JwtTokenInfo(oldJwtId, Timestamp.from(oldExpirationDate.toInstant()), Timestamp.from(tokenCreationDate.toInstant()), false, null, "not relevant"));
//
//        MvcResult mvcResult = mvc.perform(get("/jwt/extend-jwt-session")
//                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtTokenString)))
//                .andExpect(status().isOk())
//                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(notNullValue())))
//                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), is(-1)))
//                .andExpect(cookie().value(legacyPortalIntegrationConfig.getSessionCookieName(), is(notNullValue())))
//                .andExpect(cookie().maxAge(legacyPortalIntegrationConfig.getSessionCookieName(), is(-1)))
//                .andReturn();
//
//        Cookie extendedSessionInfo = mvcResult.getResponse().getCookie(jwtSignatureConfig.getCookieName());
//        UserInfo userInfo = jwtUtils.decodeJwtTokenFromCookie(extendedSessionInfo);
//        assertThat(userInfo.getLoginExpireDate(), greaterThanOrEqualTo(DateUtils.addMinutes(tokenCreationDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())));
//
//
//        //check that userinfo is updated
//        mvc.perform(
//                get("/jwt/userinfo")
//                        .cookie(extendedSessionInfo))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("loggedInDate", is(tokenCreationDate.getTime())))
//                .andExpect(jsonPath("loginExpireDate", greaterThanOrEqualTo(DateUtils.addMinutes(tokenCreationDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes()).getTime())));
//
//        //check that old cookie is blacklisted
//        assertThat(jwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(oldJwtId), notNullValue());
//
//    }

//    @Test
//     void testSessionExtensionUsingJwtCookieForNonEstonianPersonalCode() throws Exception {
//
//        Calendar instance = Calendar.getInstance();
//        instance.set(Calendar.MILLISECOND, 0);
//        Date tokenCreationDate = instance.getTime();
//        instance.add(Calendar.MINUTE, 1);
//        Date oldExpirationDate = instance.getTime();
//        instance.add(Calendar.MINUTE, legacyPortalIntegrationConfig.getSessionTimeoutMinutes());
//
//        UUID oldJwtId = UUID.randomUUID();
//        String personalCode = "LT11223344556";
//        String jwtTokenString = getJwtTokenString(
//                tokenCreationDate,
//                oldExpirationDate, jwtSignatureConfig.getIssuer(), oldJwtId.toString(), Collections.singletonMap("personalCode", personalCode), personalCode);
//
//        jwtTokenInfoRepository.save(new JwtTokenInfo(oldJwtId, Timestamp.from(oldExpirationDate.toInstant()), Timestamp.from(tokenCreationDate.toInstant()), false, null, "not relevant"));
//
//        MvcResult mvcResult = mvc.perform(get("/jwt/extend-jwt-session")
//                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtTokenString)))
//                .andExpect(status().isOk())
//                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(notNullValue())))
//                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), is(-1)))
//                .andExpect(cookie().doesNotExist(legacyPortalIntegrationConfig.getSessionCookieName()))
//                .andReturn();
//
//        Cookie extendedSessionInfo = mvcResult.getResponse().getCookie(jwtSignatureConfig.getCookieName());
//        UserInfo userInfo = jwtUtils.decodeJwtTokenFromCookie(extendedSessionInfo);
//        assertThat(userInfo.getLoginExpireDate(), greaterThanOrEqualTo(DateUtils.addMinutes(tokenCreationDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())));
//
//
//        //check that userinfo is updated
//        mvc.perform(
//                get("/jwt/userinfo")
//                        .cookie(extendedSessionInfo))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("loggedInDate", is(tokenCreationDate.getTime())))
//                .andExpect(jsonPath("loginExpireDate", greaterThanOrEqualTo(DateUtils.addMinutes(tokenCreationDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes()).getTime())));
//
//        //check that old cookie is blacklisted
//        assertThat(jwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(oldJwtId), notNullValue());
//
//    }

//    @Test
//     void testJwtRoleChange() throws Exception {
//
//        Calendar instance = Calendar.getInstance();
//        instance.set(Calendar.MILLISECOND, 0);
//        Date tokenCreationDate = instance.getTime();
//        instance.add(Calendar.MINUTE, 1);
//        Date oldExpirationDate = instance.getTime();
//        instance.add(Calendar.MINUTE, legacyPortalIntegrationConfig.getSessionTimeoutMinutes());
//
//        UUID oldJwtId = UUID.randomUUID();
//        String personalCode = "LT11223344556";
//        String jwtTokenString = getJwtTokenString(
//                tokenCreationDate,
//                oldExpirationDate, jwtSignatureConfig.getIssuer(), oldJwtId.toString(), Collections.singletonMap("personalCode", personalCode), personalCode);
//
//        jwtTokenInfoRepository.save(new JwtTokenInfo(oldJwtId, Timestamp.from(oldExpirationDate.toInstant()), Timestamp.from(tokenCreationDate.toInstant()), false, null, "not relevant"));
//
//        Map<String, Object> claims = new HashMap<>();
//        claims.put(roleRestrctionsAttr, Lists.newArrayList("LT99887766554", "LT99887766555"));
//        SignedJWT roleRestrictionsJwt = jwtUtils.getSignedJWTWithClaims(UUID.randomUUID(), "", claims, new Date(), new Date(new Date().getTime() + 60000));
//        Cookie roleRestrictionsCookie = new Cookie(roleRestrictionsCookieName, roleRestrictionsJwt.serialize());
//        Cookie jwtCookie = new Cookie(jwtSignatureConfig.getCookieName(), jwtTokenString);
//
//        MvcResult mvcResult = mvc.perform(post("/jwt/change-jwt-role")
//                .content("{\"id\":\"LT99887766554\"}")
//                .cookie(jwtCookie, roleRestrictionsCookie))
//                .andExpect(status().isOk())
//                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(notNullValue())))
//                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), is(-1)))
//                .andExpect(cookie().doesNotExist(legacyPortalIntegrationConfig.getSessionCookieName()))
//                .andReturn();
//
//        String jwtString = mvcResult.getResponse().getContentAsString();
//        SignedJWT roleChangeJwt = SignedJWT.parse(jwtString);
//        assertEquals("LT99887766554" ,roleChangeJwt.getJWTClaimsSet().getClaim("personalCode"));
//        assertThat(jwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(oldJwtId), notNullValue());
//    }


    private SessionsEntity createSessionsEntity(String legacySessionId, LocalDateTime validFrom, LocalDateTime validTo) {
        SessionsEntity sessionsEntity = new SessionsEntity();
        sessionsEntity.setSessionId(legacySessionId);
        sessionsEntity.setLastModified(LocalDateTime.now());
        sessionsEntity.setValidFrom(validFrom.atOffset(ZoneOffset.UTC).toLocalDateTime());
        sessionsEntity.setValidTo(validTo.atOffset(ZoneOffset.UTC).toLocalDateTime());

        return sessionsEntity;
    }

    private Date convertToDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.truncatedTo(ChronoUnit.SECONDS).atZone(ZoneId.systemDefault()).toInstant());
    }
}
