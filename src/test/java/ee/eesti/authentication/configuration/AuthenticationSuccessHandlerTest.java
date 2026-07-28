package ee.eesti.authentication.configuration;

import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.service.JwtTokenInfoService;
import ee.eesti.authentication.service.SessionsService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthenticationSuccessHandlerTest {

    private JwtUtils jwtUtils;
    private AuthenticationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        SessionsService sessionsService = mock(SessionsService.class);
        LegacyPortalIntegrationConfig legacyPortalIntegrationConfig = mock(LegacyPortalIntegrationConfig.class);
        when(legacyPortalIntegrationConfig.getSessionTimeoutMinutes()).thenReturn(30);
        when(legacyPortalIntegrationConfig.getRedirectUrlAttribute()).thenReturn("url_redirect");
        when(legacyPortalIntegrationConfig.getRequestIpAttribute()).thenReturn("request_ip");
        JwtTokenInfoService jwtTokenInfoService = mock(JwtTokenInfoService.class);
        jwtUtils = mock(JwtUtils.class);
        when(jwtUtils.createSignedJwt(any(), any())).thenReturn(mock(SignedJWT.class));
        when(jwtUtils.getJwtCookie(any())).thenReturn(new Cookie("JWTTOKEN", "test"));

        handler = new AuthenticationSuccessHandler(sessionsService, legacyPortalIntegrationConfig, jwtTokenInfoService, jwtUtils);
    }

    @Test
    void govssoFlatClaimsArePickedUpDirectly() throws Exception {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "EE12345678901");
        attributes.put("given_name", "Jaan");
        attributes.put("family_name", "Tamm");
        attributes.put("amr", new ArrayList<>(Collections.singletonList("mID")));

        OAuth2AuthenticationToken authentication = authenticationFor(attributes, SecurityConfiguration.REGISTRATION_ID_GOVSSO);

        handler.onAuthenticationSuccess(requestWithCallbackUrl(), new MockHttpServletResponse(), authentication);

        UserInfo capturedUserInfo = captureUserInfo();
        assertEquals("Jaan", capturedUserInfo.getFirstName());
        assertEquals("Tamm", capturedUserInfo.getLastName());
        assertEquals("EE12345678901", capturedUserInfo.getPersonalCode());
    }

    @Test
    void taraNestedProfileAttributesAreStillPickedUpCorrectly() throws Exception {
        LinkedTreeMap<String, Object> profileAttributes = new LinkedTreeMap<>();
        profileAttributes.put("given_name", "Mari");
        profileAttributes.put("family_name", "Mets");

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "EE98765432109");
        attributes.put("profile_attributes", profileAttributes);
        attributes.put("amr", new ArrayList<>(Collections.singletonList("idcard")));

        OAuth2AuthenticationToken authentication = authenticationFor(attributes, SecurityConfiguration.REGISTRATION_ID_TARA);

        handler.onAuthenticationSuccess(requestWithCallbackUrl(), new MockHttpServletResponse(), authentication);

        UserInfo capturedUserInfo = captureUserInfo();
        assertEquals("Mari", capturedUserInfo.getFirstName());
        assertEquals("Mets", capturedUserInfo.getLastName());
        assertEquals("EE98765432109", capturedUserInfo.getPersonalCode());
    }

    private UserInfo captureUserInfo() {
        ArgumentCaptor<UserInfo> userInfoCaptor = ArgumentCaptor.forClass(UserInfo.class);
        org.mockito.Mockito.verify(jwtUtils).createSignedJwt(any(), userInfoCaptor.capture());
        return userInfoCaptor.getValue();
    }

    private OAuth2AuthenticationToken authenticationFor(Map<String, Object> attributes, String registrationId) {
        OAuth2User oAuth2User = new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
        return new OAuth2AuthenticationToken(oAuth2User, oAuth2User.getAuthorities(), registrationId);
    }

    private MockHttpServletRequest requestWithCallbackUrl() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(CustomSessionAttributeSecurityFilter.CALLBACK_URL, "https://test.com");
        request.setSession(session);
        return request;
    }
}
