package ee.eesti.authentication.service;

import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.enums.ChannelType;
import ee.eesti.authentication.enums.Language;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

class SessionsServiceTest extends AbstractSpringBasedTest {
    private static final ChannelType CHANNEL = ChannelType.AUTENTIMATA;
    private static final String MOBILE_NUMBER = "54545454";
    private static final String FIRST_NAME = "John";
    private static final String LAST_NAME = "Doe";
    private static final String PERSONAL_CODE = "EE38833883383";
    private static final String DEFAULT_REDIRECT_URL = "https://www.arendus.eesti.ee/est";
    private static final String DEFAULT_IP = "127.0.0.1";

    @Autowired
    private SessionsService sessionsService;
    @Autowired
    private SessionsRepository sessionsRepository;
    @Mock(lenient = true)
    private MockHttpServletRequest mockHttpServletRequest;
    @Autowired
    private LegacyPortalIntegrationConfig config;
    @Autowired
    private JwtUtils jwtUtils;

    @BeforeEach
    void init() {
        sessionsRepository.deleteAll();

        HttpSession mockHttpSession = new MockHttpSession();
        mockHttpSession.setAttribute(config.getRedirectUrlAttribute(), DEFAULT_REDIRECT_URL);
        mockHttpSession.setAttribute(config.getRequestIpAttribute(), DEFAULT_IP);
        doReturn(mockHttpSession).when(mockHttpServletRequest).getSession();
    }

    @Test
    @Transactional
    void testSessionEntityCreation() {
        assertNotNull(mockHttpServletRequest.getSession());

        sessionsService.createSessionEntity(
                getUserInfo(),
                CHANNEL,
                SessionsService.createSessionId(),
                MOBILE_NUMBER,
                (String) mockHttpServletRequest.getSession().getAttribute(config.getRequestIpAttribute()),
                Language.getByUri((String) mockHttpServletRequest.getSession().getAttribute(config.getRedirectUrlAttribute())).name().toLowerCase(),
                mockHttpServletRequest.getHeader("User-Agent"));

        List<SessionsEntity> sessionsEntities = sessionsService.getSessionIds();

        assertEquals(1, sessionsEntities.size());
        assertEquals(FIRST_NAME, sessionsEntities.get(0).getGivenname());
    }

    @Test
    @Transactional
    void testCookieCreation() {
        Cookie cookie = jwtUtils.getLegacySessionCookie(
                mockHttpServletRequest,
                sessionsService.openLegacyPortalLoginSession(mockHttpServletRequest, getUserInfo(), CHANNEL, MOBILE_NUMBER),
                false);

        List<SessionsEntity> sessionsEntities = sessionsService.getSessionIds();

        assertEquals(sessionsEntities.get(0).getSessionId(), cookie.getValue());
    }

    @Test
    @Transactional
    void testCreateSessionEntityThrowsForNonEstonianPersonalCode() {
        UserInfo userInfo = getUserInfo();
        userInfo.setPersonalCode("LT38833883383");

        assertThrows(IllegalArgumentException.class, () ->
                sessionsService.createSessionEntity(
                        userInfo,
                        CHANNEL,
                        SessionsService.createSessionId(),
                        MOBILE_NUMBER,
                        DEFAULT_IP,
                        "eng",
                        "some-user-agent"));
    }

    @Test
    @Transactional
    void testOpenLegacyPortalLoginSessionReadsIpAndLanguageFromExistingHttpSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(config.getRequestIpAttribute(), DEFAULT_IP);
        request.getSession().setAttribute(config.getRedirectUrlAttribute(), "https://www.arendus.eesti.ee/eng/portal");

        SessionsEntity sessionsEntity = sessionsService.openLegacyPortalLoginSession(request, getUserInfo(), CHANNEL, MOBILE_NUMBER);

        assertEquals(DEFAULT_IP, sessionsEntity.getIp());
        assertTrue(sessionsEntity.getParams().contains("{LANG, en}"), sessionsEntity.getParams());
    }

    @Test
    @Transactional
    void testOpenLegacyPortalLoginSessionReusesSessionIdFromActiveCookie() {
        String existingSessionId = SessionsService.createSessionId();
        SessionsEntity existingSession = new SessionsEntity();
        existingSession.setSessionId(existingSessionId);
        existingSession.setValidFrom(LocalDateTime.now());
        existingSession.setValidTo(LocalDateTime.now().plusMinutes(30));
        sessionsRepository.saveAndFlush(existingSession);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie(config.getSessionCookieName(), existingSessionId));

        sessionsService.openLegacyPortalLoginSession(request, getUserInfo(), CHANNEL, MOBILE_NUMBER);

        // the cookie's sessionId should have been reused (createSessionEntity upserts by sessionId),
        // rather than a brand new session row being created alongside it
        assertEquals(1, sessionsService.getSessionIds().size());
        assertEquals(existingSessionId, sessionsService.getSessionIds().get(0).getSessionId());
    }

    @Test
    @Transactional
    void testOpenLegacyPortalLoginSessionGeneratesNewIdWhenMultipleActiveSessionsMatchCookies() {
        String sessionIdA = SessionsService.createSessionId();
        String sessionIdB = SessionsService.createSessionId();
        for (String sessionId : List.of(sessionIdA, sessionIdB)) {
            SessionsEntity entity = new SessionsEntity();
            entity.setSessionId(sessionId);
            entity.setValidFrom(LocalDateTime.now());
            entity.setValidTo(LocalDateTime.now().plusMinutes(30));
            sessionsRepository.saveAndFlush(entity);
        }

        // legacy portal behaviour: several cookies can share the same name with only one actually active
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie(config.getSessionCookieName(), sessionIdA),
                new Cookie(config.getSessionCookieName(), sessionIdB));

        sessionsService.openLegacyPortalLoginSession(request, getUserInfo(), CHANNEL, MOBILE_NUMBER);

        // ambiguous (2 active sessions matched) - a brand new session id must be generated instead of
        // reusing either candidate
        List<SessionsEntity> allSessions = sessionsService.getSessionIds();
        assertEquals(3, allSessions.size());
        assertTrue(allSessions.stream().anyMatch(s ->
                !s.getSessionId().equals(sessionIdA) && !s.getSessionId().equals(sessionIdB)));
    }

    private UserInfo getUserInfo() {
        UserInfo userInfo = new UserInfo();
        userInfo.setFirstName(FIRST_NAME);
        userInfo.setLastName(LAST_NAME);
        userInfo.setPersonalCode(PERSONAL_CODE);
        return userInfo;
    }
}
