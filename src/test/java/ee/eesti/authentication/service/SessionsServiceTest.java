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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    private UserInfo getUserInfo() {
        UserInfo userInfo = new UserInfo();
        userInfo.setFirstName(FIRST_NAME);
        userInfo.setLastName(LAST_NAME);
        userInfo.setPersonalCode(PERSONAL_CODE);
        return userInfo;
    }
}
