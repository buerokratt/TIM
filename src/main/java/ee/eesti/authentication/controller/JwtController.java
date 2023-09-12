package ee.eesti.authentication.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.configuration.AuthenticationSuccessHandler;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.enums.ChannelType;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import ee.eesti.authentication.service.JwtTokenInfoService;
import ee.eesti.authentication.service.SessionsService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.Tag;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.sql.Timestamp;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import rig.commons.aop.Timed;

/**
 * Controller to handle all JWT related endpoints
 */

@CrossOrigin(originPatterns = "*", allowCredentials = "true")
@RestController
@RequestMapping("/jwt")
@Slf4j
@Api(value="jwt", tags = {"jwt"})
@SwaggerDefinition(tags = {
        @Tag(name = "jwt", description = "Operations pertaining to jwt in Tara Integration module")
})
@Timed
public class JwtController {

    private final JwtSignatureConfig jwtSignatureConfig;

    private final LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;

    private final JwtUtils jwtUtils;

    private final JwtTokenInfoRepository jwtTokenInfoRepository;

    private final JwtTokenInfoService jwtTokenInfoService;

    private final SessionsService sessionsService;

    private final SessionsRepository sessionsRepository;

    @Value("#{'${jwt-integration.cookiesToBlacklist:JWTTOKEN,PHPSESSID}'.split(',')}")
    private List<String> cookiesToBlacklist;

    @Value("${role.restrictions.cookie.name:ROLE_RESTRICTIONS}")
    private String roleRestrictionsCookieName;

    @Value("${role.restrictions.cookie.attr:role_restrictions}")
    private String roleRestrctionsAttr;

    private String publicKey;

    private static final ResponseEntity<?> emptyOkResponse = ResponseEntity.ok().build();

    private static final ResponseEntity<?> badRequest = ResponseEntity.badRequest().build();

    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtController(JwtSignatureConfig jwtSignatureConfig, LegacyPortalIntegrationConfig legacyPortalIntegrationConfig, JwtUtils jwtUtils, JWSVerifier verifier, JwtTokenInfoRepository jwtTokenInfoRepository, JwtTokenInfoService jwtTokenInfoService, SessionsService sessionsService, SessionsRepository sessionsRepository) {
        this.jwtSignatureConfig = jwtSignatureConfig;
        this.legacyPortalIntegrationConfig = legacyPortalIntegrationConfig;
        this.jwtUtils = jwtUtils;
        this.jwtTokenInfoRepository = jwtTokenInfoRepository;
        this.jwtTokenInfoService = jwtTokenInfoService;
        this.sessionsService = sessionsService;
        this.sessionsRepository = sessionsRepository;
    }

    /**
     * load public key (will be used by various methods of this controller) from KeyStore
     */
    @PostConstruct
    public void postConstruct() {
        publicKey = loadPublicKey();
    }

    /**
     *
     * @return public key
     */
    @ApiOperation(value = "Obtain the jwt verification key", response = String.class)
    @ApiResponse(code = 200, response = String.class, message = "Successfully retrieved list")
    @GetMapping("/verification-key")
    public String getJwtVerificationKey() {
        return publicKey;
    }

    private String loadPublicKey() {
        log.debug("loading verification key");
        KeyStore jwtSignKeyStore;
        try {
            jwtSignKeyStore = KeyStore.getInstance(jwtSignatureConfig.getKeyStoreType());
            jwtSignKeyStore.load(jwtSignatureConfig.getKeyStore().getInputStream(), jwtSignatureConfig.getKeyStorePassword().toCharArray());

            Certificate certificate = jwtSignKeyStore.getCertificate(jwtSignatureConfig.getKeyAlias());

            return String.format("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
                    Base64.toBase64String(certificate.getPublicKey().getEncoded()));
        } catch (Exception e) {
            log.error("cannot load public key", e);
            throw new IllegalStateException(e);
        }
    }

    /**
     *
     * @param jwtTokenToCheck JWT to verify
     * @return response with status 200 if verification successful and with status 400 if not
     */
    @ApiOperation(value = "Verify the jwt token", response = ResponseEntity.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, response = ResponseEntity.class, message = "Verification successful"),
    })
    @PostMapping("/verify")
    public ResponseEntity<?> verifyToken(
            @ApiParam(name = "jwtTokenToCheck", value = "Jwt token to verify")
            @RequestBody String jwtTokenToCheck
    ) {
        boolean valid = jwtUtils.isJwtTokenValid(jwtTokenToCheck, false);

        return valid
                ? emptyOkResponse
                : ResponseEntity.badRequest().build();
    }

    /**
     *
     * @param request incoming request
     * @return if successful returns user's info as decoded from JWT aquired from  request cookie
     */
    @ApiOperation(value = "decode the cookie into userInfo, does not check if the JWT is expired or not", response = ResponseEntity.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, response = ResponseEntity.class, message = "decoding done successfully"),
            @ApiResponse(code = 400, message = "decoding failed")
    })
    @GetMapping("/userinfo")
    public ResponseEntity<?> decodeJwtFromCookie(HttpServletRequest request) {

        if (cookiesNotPresent(request)) return badRequest;

        Cookie cookie = Arrays.stream(request.getCookies())
                .filter(getFindByCookieNamePredicate(jwtSignatureConfig.getCookieName()))
                .findFirst()
                .orElse(null);

        if (cookie == null) {
            log.debug("cookie not found");
            return badRequest;
        }

        if (!jwtUtils.isJwtTokenValid(cookie.getValue(), false)) {
            log.debug("cookie is invalid, cookie value: {}", cookie.getValue());
            return badRequest;
        }

        UserInfo userInfo = jwtUtils.decodeJwtTokenFromCookie(cookie);

        if (userInfo == null) {
            log.debug("userinfo cannot be parsed from cookie: {} ", cookie.getValue());
        }

        return  userInfo == null
                ? badRequest
                : new ResponseEntity<>(userInfo, HttpStatus.OK);
    }

    private boolean cookiesNotPresent(HttpServletRequest request) {
        return request.getCookies() == null || request.getCookies().length == 0;
    }

    private Predicate<Cookie> getFindByCookieNamePredicate(String cookieName) {
        return cookie -> cookieName.equals(cookie.getName());
    }

    @ApiOperation(value = "extend the JWT", response = ResponseEntity.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, response = ResponseEntity.class, message = "JWT extended successfully"),
            @ApiResponse(code = 400, message = "extending the JWT failed")
    })
    @PostMapping("/change-jwt-role")
    public ResponseEntity<?> changeJwtSessionRole(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (cookiesNotPresent(request)) return badRequest;

        String requestStr = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
        JsonNode jsonNode = objectMapper.readTree(requestStr);
        String roleChangePersonalCode = jsonNode.has("id") ? jsonNode.get("id").asText() : null;

        if (roleChangePersonalCode == null)
            return badRequest;

        Cookie jwtCookie = Arrays.stream(request.getCookies())
                .filter(getFindByCookieNamePredicate(jwtSignatureConfig.getCookieName()))
                .findFirst()
                .orElse(null);

        UserInfo userInfoFromJwt = jwtUtils.decodeJwtTokenFromCookie(jwtCookie);
        boolean jwtCookieValid = jwtCookie != null && jwtUtils.isJwtTokenValid(jwtCookie.getValue(), false);

        if (userInfoFromJwt != null && jwtCookieValid) {
            String oldJwtId;
            try {
                SignedJWT parse = SignedJWT.parse(jwtCookie.getValue());
                oldJwtId = parse.getJWTClaimsSet().getJWTID();

                JwtTokenInfo jwtTokenInfo = jwtTokenInfoRepository
                        .findById(UUID.fromString(oldJwtId))
                        .orElseThrow(() -> new IllegalArgumentException("old jwt token info is not found for blacklisting"));

                blacklist(jwtTokenInfo);

            } catch (Exception e) {
                log.error("Failure while changing role", e);
                throw new RuntimeException(e);
            }

            if (isValidChangeRole(roleChangePersonalCode, request.getCookies())) {
                userInfoFromJwt.setPersonalCode(roleChangePersonalCode);
            }
        }

        return emptyOkResponse;
    }

    /**
     *
     * @param request incoming request
     * @param response current response
     * @return  returns 200 status response regardless if extending the cookie was successful or not
     */
    @ApiOperation(value = "extend the JWT", response = ResponseEntity.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, response = ResponseEntity.class, message = "JWT extended successfully"),
            @ApiResponse(code = 400, message = "extending the JWT failed")
    })
    @GetMapping("/extend-jwt-session")
    public ResponseEntity<?> extendJwtSession(HttpServletRequest request, HttpServletResponse response) {

        if (cookiesNotPresent(request)) return badRequest;

        Cookie jwtCookie = Arrays.stream(request.getCookies())
                .filter(getFindByCookieNamePredicate(jwtSignatureConfig.getCookieName()))
                .findFirst()
                .orElse(null);

        Cookie legacySessionCookie = Arrays.stream(request.getCookies())
                .filter(getFindByCookieNamePredicate(legacyPortalIntegrationConfig.getSessionCookieName()))
                .findFirst()
                .orElse(null);

        UserInfo userInfoFromJwt = jwtUtils.decodeJwtTokenFromCookie(jwtCookie);
        boolean jwtCookieValid = jwtCookie != null && jwtUtils.isJwtTokenValid(jwtCookie.getValue(), false);

        // first try to extend the JWT from JWT cookie.
        if (userInfoFromJwt != null && jwtCookieValid) {

            String oldJwtId;
            try {
                SignedJWT parse = SignedJWT.parse(jwtCookie.getValue());
                oldJwtId = parse.getJWTClaimsSet().getJWTID();
            } catch (ParseException e) {
                log.error("cannot parse JWT uid. ");
                throw new IllegalStateException(e);
            }

            try {
                JwtTokenInfo jwtTokenInfo = jwtTokenInfoRepository
                        .findById(UUID.fromString(oldJwtId))
                        .orElseThrow(() -> new IllegalArgumentException("old jwt token info is not found for blacklisting"));
                blacklist(jwtTokenInfo);
            } catch (Exception e) {
                log.error("exception in blacklisting old token before extension session", e);
                throw new RuntimeException(e);
            }
        }

        if (legacySessionCookie != null && legacySessionCookie.getValue() != null &&
                !AuthenticationSuccessHandler.DEFAULT_LEGACY_SESSION_ID_VALUE.equals(legacySessionCookie.getValue())) {
            // there is no JWT cookie found, try the legacy session id cookie instead
            Optional<SessionsEntity> stillValidLegacySession = sessionsRepository
                    .findBySessionId(legacySessionCookie.getValue())
                    .filter(sessionsEntity -> sessionsEntity.getValidTo().isAfter(LocalDateTime.now()));

            stillValidLegacySession.ifPresent(sessionsEntity -> extendSessionObtainedFromLegacySystem(sessionsEntity, request, response));
        }

        return emptyOkResponse;
    }

    private void extendSessionObtainedFromLegacySystem(SessionsEntity sessionEntity,
                                                       HttpServletRequest request,
                                                       HttpServletResponse response) {

        sessionEntity.setLastModified(LocalDateTime.now());
        sessionEntity.setValidTo(LocalDateTime.now().plusMinutes(legacyPortalIntegrationConfig.getSessionTimeoutMinutes()));
        sessionsRepository.save(sessionEntity);

        UserInfo userInfo = new UserInfo();
        userInfo.setPersonalCode(sessionEntity.getPersonalCode());
        userInfo.setAuthenticatedAs(sessionEntity.getPersonalCode());
        userInfo.setAuthenticatedAs(sessionEntity.getHash());
        userInfo.setFirstName(sessionEntity.getGivenname());
        userInfo.setLastName(sessionEntity.getSurname());
        userInfo.setLoggedInDate(convertLocalDateTimeToDate(sessionEntity.getValidFrom()));
        userInfo.setLoginExpireDate(convertLocalDateTimeToDate(sessionEntity.getValidTo()));
        userInfo.setAuthMethod(convertChannelToAmr(sessionEntity.getChannel()));

        UUID jwtTokenId = UUID.randomUUID();
        SignedJWT signedJwt = jwtUtils.createSignedJwt(jwtTokenId, userInfo);
        jwtTokenInfoService.createJwtTokenInfo(jwtTokenId, sessionEntity.getSessionId(), new Timestamp(userInfo.getLoginExpireDate().getTime()));


        Cookie legacySessionCookie = jwtUtils.getLegacySessionCookie(request, sessionEntity, true);
        response.addCookie(legacySessionCookie);

        response.addCookie(jwtUtils.getJwtCookie(signedJwt));
    }

    private Date convertLocalDateTimeToDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    private String convertChannelToAmr(String channel) {
      return Optional.ofNullable(ChannelType.getByChannel(channel)).orElse(ChannelType.DEFAULT).getAmr();
    }

    @ApiOperation(value = "Mark the session details as blacklisted", response = ResponseEntity.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, response = ResponseEntity.class, message = "always 200"),

    })
    @PostMapping("/blacklist")
    @Transactional
    public ResponseEntity<?> performBlacklist(
            @ApiParam(name = "jwt", value = "Jwt token id to blacklist")
            @RequestParam(name = "jwt", required = false) String jwtTokenId,
            @ApiParam(name = "sessionId", value = "Session id to blacklist")
            @RequestParam(name = "sessionId", required = false) String sessionId,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        // find the jwt from cookie

        String jwtFromCookie = null;
        if (request.getCookies() != null) {
            jwtFromCookie = Arrays.stream(request.getCookies())
                    .filter(getFindByCookieNamePredicate(jwtSignatureConfig.getCookieName()))
                    .findFirst()
                    .map(Cookie::getValue)
                    .orElse(null);
        }

        if (jwtTokenId == null && sessionId == null && jwtFromCookie == null) {
            return emptyOkResponse;
        }

        Optional<JwtTokenInfo> jwtTokenInfoOptional = Optional.empty();
        // ideally the session_id should be unique
        if (jwtFromCookie != null) {

            try {
                SignedJWT jwt = SignedJWT.parse(jwtFromCookie);
                jwtTokenInfoOptional = jwtTokenInfoRepository.findById(UUID.fromString(jwt.getJWTClaimsSet().getJWTID()));
            } catch (ParseException e) {
                log.warn("could not parse JWT from cookie");
            }
        } else if (jwtTokenId != null) {
            jwtTokenInfoOptional = jwtTokenInfoRepository.findById(UUID.fromString(jwtTokenId));
        }

        jwtTokenInfoOptional.ifPresent(this::blacklist);

        for (Cookie c : request.getCookies()) {
            if (this.isBlackListable(c)) {
                this.removeCookie(response, c, legacyPortalIntegrationConfig.getSessionCookieDomain(), "/");
                this.removeCookie(response, c, request.getServerName(), "/");
                this.removeCookie(response, c, request.getServerName(), request.getContextPath());
                this.removeCookie(response, c, request.getServerName(), request.getContextPath().concat("/jwt"));
            }
        }

        return emptyOkResponse;
    }

    private void removeCookie(HttpServletResponse response, Cookie c, String domain, String path) {
        Cookie cookie = new Cookie(c.getName(), null);
        cookie.setDomain(domain);
        cookie.setMaxAge(0);
        cookie.setSecure(c.getSecure());
        cookie.setPath(path);
        response.addCookie(cookie);
    }

    private boolean isBlackListable(Cookie c) {
        for (String cookieName : cookiesToBlacklist) {
            if (c.getName().trim().equalsIgnoreCase(cookieName.trim())) {
                return true;
            }
        }
        return false;
    }

    private void blacklist(JwtTokenInfo jwtTokenInfo) {
        jwtTokenInfo.setBlacklisted(true);
        jwtTokenInfo.setBlacklistedDate(new Timestamp(System.currentTimeMillis()));

        jwtTokenInfoRepository.save(jwtTokenInfo);
        log.debug("jwtTokenInfo blacklisted ({})", jwtTokenInfo);
    }

    private boolean isValidChangeRole(String personalCode, Cookie[] cookies) {
        Cookie roleRestrictionsCookie = null;

        if (personalCode == null)
            return false;

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(roleRestrictionsCookieName)) {
                roleRestrictionsCookie = cookie;
            }
        }

        if (roleRestrictionsCookie == null)
            return false;

        if (!jwtUtils.isJwtTokenValid(roleRestrictionsCookie.getValue(), true))
            return false;

        try {
            SignedJWT signedJWT = SignedJWT.parse(roleRestrictionsCookie.getValue());
            String[] roleList = signedJWT.getJWTClaimsSet().getStringArrayClaim(roleRestrctionsAttr);
            boolean valid = Arrays.asList(roleList).contains(personalCode);
            log.info("Incoming id {} in list {}, {}", personalCode, Collections.singletonList(roleList), valid);
            return valid;
        } catch (Throwable t) {
            return false;
        }
    }
}
