package ee.eesti.authentication.configuration;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.enums.ChannelType;
import ee.eesti.authentication.service.JwtTokenInfoService;
import ee.eesti.authentication.service.SessionsService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

import static ee.eesti.authentication.configuration.CustomSessionAttributeSecurityFilter.CALLBACK_URL;
import static ee.eesti.authentication.configuration.CustomSessionAttributeSecurityFilter.LEGACY;

/**
 * Handler for authentication success
 */
@Component
@Slf4j
public class AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    public static final String DEFAULT_LEGACY_SESSION_ID_VALUE = "-1";

    private final SessionsService sessionsService;

    private final LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;

    private final JwtUtils jwtUtils;

    private final JwtTokenInfoService jwtTokenInfoService;

    public AuthenticationSuccessHandler(SessionsService sessionsService,
                                        LegacyPortalIntegrationConfig legacyPortalIntegrationConfig,
                                        JwtTokenInfoService jwtTokenInfoService,
                                        @Lazy JwtUtils jwtUtils) {
        this.sessionsService = sessionsService;
        this.legacyPortalIntegrationConfig = legacyPortalIntegrationConfig;
        this.jwtTokenInfoService = jwtTokenInfoService;
        this.jwtUtils = jwtUtils;
    }

    /**
     * Response will do a redirect to legacy portal or to callback url depending on authentication details.
     * If details do not provide callback url or define a legacy session then jwtToken is written to the response.
     * Session attributes are set depending on authentication details.
     *
     * @param request        incoming request
     * @param response       current response
     * @param authentication successful authentication
     * @throws IOException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        HttpSession session = request.getSession();
        OAuth2AuthenticationToken casted = (OAuth2AuthenticationToken) authentication;

        UserInfo userInfo = new UserInfo();
        String personalCode = (String) casted.getPrincipal().getAttributes().get("sub");
        JSONObject profileAttributes = (JSONObject) casted.getPrincipal().getAttributes().get("profile_attributes");

        userInfo.setPersonalCode(personalCode);
        userInfo.setAuthenticatedAs(personalCode);
        userInfo.setHash(getUniqueRandomHash());
        userInfo.setFirstName(profileAttributes.getAsString("given_name"));
        userInfo.setLastName(profileAttributes.getAsString("family_name"));
        userInfo.setLoggedInDate(new Date());
        userInfo.setLoginExpireDate(
                DateUtils.addMinutes(
                        userInfo.getLoggedInDate(),
                        legacyPortalIntegrationConfig.getSessionTimeoutMinutes()));

        ((OAuth2AuthenticationToken) authentication).setDetails(userInfo);

        ArrayList amrArray = (ArrayList) casted.getPrincipal().getAttributes().get("amr");
        String amr;
        // TODO: Will amr ever be empty on successful authentication??
        if (amrArray == null || amrArray.isEmpty()) {
            amr = "mID";
        } else {
            amr = amrArray.get(0).toString();
        }
        userInfo.setAuthMethod(amr);

        UUID jwtTokenId = UUID.randomUUID();
        SignedJWT signedJWT = jwtUtils.createSignedJwt(jwtTokenId, userInfo);
        jwtTokenInfoService.createJwtTokenInfo(
                jwtTokenId,
                    UUID.randomUUID().toString(),
                new Timestamp(userInfo.getLoginExpireDate().getTime()));

        response.addCookie(jwtUtils.getJwtCookie(signedJWT));

        if (session.getAttribute(CALLBACK_URL) != null) {
            log.debug("redirecting back callback_url {}", session.getAttribute(CALLBACK_URL));
            response.sendRedirect((String) session.getAttribute(CALLBACK_URL));
        }
        else {
            log.debug("no redirect URL is found, returning JWT token instead");
            response.getWriter().write(signedJWT.serialize());
        }

        session.removeAttribute(LEGACY);
        session.removeAttribute(CALLBACK_URL);
        session.removeAttribute(legacyPortalIntegrationConfig.getRedirectUrlAttribute());
        session.removeAttribute(legacyPortalIntegrationConfig.getRequestIpAttribute());
        session.removeAttribute(CustomSessionAttributeSecurityFilter.LEGACY);
    }

    private String getUniqueRandomHash() {
        return UUID.randomUUID().toString().concat(UUID.randomUUID().toString())
                .replace("-", "");
    }

}
