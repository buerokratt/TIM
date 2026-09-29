package ee.eesti.authentication.configuration;

import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CustomSessionAttributeSecurityFilterTest {

    private static final String REQUEST_IP_ATTRIBUTE = "request_ip";
    private static final String REQUEST_IP_HEADER = "X-FORWARDED-FOR";
    private static final String LEGACY_REFERER_MARKER = "https://arendus.eesti.ee/portaal";

    private CustomSessionAttributeSecurityFilter filter;

    @BeforeEach
    void setUp() {
        LegacyPortalIntegrationConfig config = mock(LegacyPortalIntegrationConfig.class);
        when(config.getLegacyPortalRefererMarker()).thenReturn(LEGACY_REFERER_MARKER);
        when(config.getRequestIpAttribute()).thenReturn(REQUEST_IP_ATTRIBUTE);
        when(config.getRequestIpHeader()).thenReturn(REQUEST_IP_HEADER);

        filter = new CustomSessionAttributeSecurityFilter(config);
        ReflectionTestUtils.setField(filter, "authSuccessRedirectUrlWhitelist", new String[]{"https://test\\.com"});
    }

    @Test
    void allowedCallbackUrlIsStoredInSession() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter(CustomSessionAttributeSecurityFilter.CALLBACK_URL, "https://test.com");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals("https://test.com", request.getSession().getAttribute(CustomSessionAttributeSecurityFilter.CALLBACK_URL));
        assertEquals(request, chain.getRequest());
    }

    @Test
    void disallowedCallbackUrlIsRejectedWithBadRequestAndChainIsNotContinued() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter(CustomSessionAttributeSecurityFilter.CALLBACK_URL, "https://evil.example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(400, response.getStatus());
        assertNull(chain.getRequest(), "filter chain should not continue past a rejected callback url");
    }

    @Test
    void legacyPortalRefererMarksSessionAsLegacy() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Referer", LEGACY_REFERER_MARKER + "/some/path");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(true, request.getSession().getAttribute("LEGACY"));
    }

    @Test
    void unrelatedRefererDoesNotMarkSessionAsLegacy() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Referer", "https://some-other-site.example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNull(request.getSession().getAttribute("LEGACY"));
    }

    @Test
    void requestIpAttributeIsSetFromConfiguredHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(REQUEST_IP_HEADER, "203.0.113.5");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals("203.0.113.5", request.getSession().getAttribute(REQUEST_IP_ATTRIBUTE));
    }

    @Test
    void requestIpFallsBackToRemoteAddrWhenHeaderMissing() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals("127.0.0.1", request.getSession().getAttribute(REQUEST_IP_ATTRIBUTE));
    }

    @Test
    void requestIpAttributeIsNotOverwrittenIfAlreadySetOnSession() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(REQUEST_IP_HEADER, "203.0.113.5");
        request.getSession().setAttribute(REQUEST_IP_ATTRIBUTE, "already-set");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals("already-set", request.getSession().getAttribute(REQUEST_IP_ATTRIBUTE));
    }
}
