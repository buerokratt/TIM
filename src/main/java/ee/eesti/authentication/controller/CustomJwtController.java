package ee.eesti.authentication.controller;


import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.CustomJwtTokenRequest;
import ee.eesti.authentication.repository.CustomJwtTokenInfoRepository;
import ee.eesti.authentication.repository.entity.CustomJwtTokenInfo;
import io.swagger.annotations.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rig.commons.aop.Timed;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.*;

/**
 * Controller to handle endpoints related to CustomJWT
 * @see CustomJwtTokenInfo
 *
 */
@CrossOrigin(originPatterns = "*", allowCredentials = "true")
@RestController
@RequestMapping("/jwt")
@Slf4j
@Api(value = "jwt", tags = {"customjwt"})
@SwaggerDefinition(tags = {
        @Tag(name = "customjwt", description = "Operations pertaining to custom jwt token")
})
@Timed
public class CustomJwtController {

    @Value("${jwt-integration.signature.secureCookie:true}")
    private boolean secureCookie;

    private final JwtUtils jwtUtils;

    private final CustomJwtTokenInfoRepository customJwtTokenInfoRepository;

    private final LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;

    private static final ResponseEntity<?> emptyOkResponse = ResponseEntity.ok().build();

    public CustomJwtController(JwtUtils jwtUtils,
                               CustomJwtTokenInfoRepository customJwtTokenInfoRepository,
                               LegacyPortalIntegrationConfig legacyPortalIntegrationConfig) {
        this.jwtUtils = jwtUtils;
        this.customJwtTokenInfoRepository = customJwtTokenInfoRepository;
        this.legacyPortalIntegrationConfig = legacyPortalIntegrationConfig;
    }

    /**
     *
     * @param request incoming request
     * @param response current response
     * @return contains custom jwtToken as string if successful, empty 200 response otherwise
     */
    @ApiOperation(value = "Create custom valid JWT token based on input params", response = String.class)
    @ApiResponse(code = 200, response = String.class, message = "Token created successfully")
    @PostMapping("/custom-jwt-generate")
    public ResponseEntity<?> createCustomJwtToken(@RequestBody @Valid CustomJwtTokenRequest request, HttpServletResponse response) {

        SignedJWT signedJWT = getCustomJwtSigned(request);

        CustomJwtTokenInfo customJwtTokenInfo = new CustomJwtTokenInfo();

        if (request.getContent() != null) {
            customJwtTokenInfo.setCustomClaimKeysFromSet(request.getContent().keySet());
        }

        try {
            customJwtTokenInfo.setJwtUuid(UUID.fromString(signedJWT.getJWTClaimsSet().getJWTID()));
            customJwtTokenInfo.setIssuedDate(Timestamp.from(signedJWT.getJWTClaimsSet().getIssueTime().toInstant()));
            customJwtTokenInfo.setExpiredDate(Timestamp.from(signedJWT.getJWTClaimsSet().getExpirationTime().toInstant()));
        } catch (ParseException e) {
            log.error("unable to get issued / expired date from generated token", e);
            return emptyOkResponse;
        }

        try {
            customJwtTokenInfoRepository.save(customJwtTokenInfo);
        } catch (Throwable t) {
            log.error("Unable to save token", t);
            return emptyOkResponse;
        }

        Cookie cookie = new Cookie(request.getJwtName(), signedJWT.serialize());
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookie);
        cookie.setDomain(legacyPortalIntegrationConfig.getSessionCookieDomain());

        response.addCookie(cookie);

        Map<String, Object> resultingJwtToken = new HashMap<>();
        resultingJwtToken.put("token", signedJWT.serialize());

        return ResponseEntity.ok(resultingJwtToken);
    }

    private SignedJWT getCustomJwtSigned(CustomJwtTokenRequest request) {
        log.debug("custom jwt token requested with: {}", request);

        Calendar calendar = Calendar.getInstance();

        Date startDate = calendar.getTime();
        calendar.add(Calendar.MINUTE, request.getExpirationInMinutes());

        Date expiryDate = calendar.getTime();

        UUID jwtTokenId = UUID.randomUUID();
        SignedJWT signedJWT = jwtUtils.getSignedJWTWithClaims(
                jwtTokenId,
                "",
                request.getContent(),
                startDate,
                expiryDate);

        log.debug("token created: {}", signedJWT.toString());
        return signedJWT;
    }

    /**
     * @param cookieName  name of cookie containing JWT
     * @param httpServletRequest incoming request
     * @return response with status 200 if JWT was found and verified or status 400 if not
     */
    @ApiOperation(value = "Verify custom valid JWT token ", response = String.class)
    @ApiResponse(code = 200, response = String.class, message = "Token verified")
    @PostMapping("/custom-jwt-verify")
    public ResponseEntity<?> verifyCustomJwtToken(@RequestBody String cookieName, HttpServletRequest httpServletRequest) {
        log.debug("verify custom jwt token called for cookieName: {}", cookieName);

        Cookie jwtCookie = getCustomJwtTokenFromRequest(cookieName, httpServletRequest);

        if (jwtCookie == null) {
            log.warn("requested cookie with name '{}' not found or empty", cookieName);
            return ResponseEntity.badRequest().build();
        }

        boolean tokenValid = jwtUtils.isJwtTokenValid(jwtCookie.getValue(), true);

        log.debug("token in cookieName {} isValid: {}", cookieName, tokenValid);

        return tokenValid
                ? emptyOkResponse
                : ResponseEntity.badRequest().build();
    }


    /**
     *
     * @param cookieName name of cookie containing JWT
     * @param httpServletRequest incoming request
     * @return response status 200 regardless if blacklisting succeeded or not
     */
    @ApiOperation(value = "Blacklist custom valid JWT token ", response = String.class)
    @ApiResponse(code = 200, response = String.class, message = "Token blacklisted")
    @PostMapping("/custom-jwt-blacklist")
    public ResponseEntity<?> blacklistCustomJwtToken(@RequestBody String cookieName, HttpServletRequest httpServletRequest) {

        Cookie cookie = getCustomJwtTokenFromRequest(cookieName, httpServletRequest);

        if (cookie == null) {
            return emptyOkResponse;
        }

        try {
            SignedJWT jwt = SignedJWT.parse(cookie.getValue());
            Optional<CustomJwtTokenInfo> tokenToBlacklist = customJwtTokenInfoRepository.findById(UUID.fromString(jwt.getJWTClaimsSet().getJWTID()));

            if (!tokenToBlacklist.isPresent()) {
                log.warn("token to be blacklisted not found JWT: {}", jwt.serialize());
            } else {
                blacklist(tokenToBlacklist.get());
            }
            return emptyOkResponse;

        } catch (Exception e) {
            log.error("failed to blacklist JWT token: " + cookie.getValue(), e);
            return emptyOkResponse;
        }
    }


    /**
     *
     * @param cookieName name of cookie containing JWT
     * @param httpServletRequest incoming request
     * @param response current response
     * @return contains new token with extended expiration if valid token was found in input otherwise
     * an empty 200 response is returned
     */
    @ApiOperation(value = "extend custom valid JWT token ", response = String.class)
    @ApiResponse(code = 200, response = String.class, message = "Token extended")
    @PostMapping("/custom-jwt-extend")
    public ResponseEntity<?> extendCustomJwtToken(@RequestBody String cookieName, HttpServletRequest httpServletRequest, HttpServletResponse response) {

        Cookie cookie = getCustomJwtTokenFromRequest(cookieName, httpServletRequest);

        if (cookie == null) {
            return emptyOkResponse;
        }

        if (!jwtUtils.isJwtTokenValid(cookie.getValue(), true)) {
            log.warn("attempted to extend invalid token {}", cookie.getValue());
            return emptyOkResponse;
        }

        try {
            SignedJWT customJwtToken = SignedJWT.parse(cookie.getValue());
            UUID jwtTokenId = UUID.fromString(customJwtToken.getJWTClaimsSet().getJWTID());
            Optional<CustomJwtTokenInfo> tokenToBlacklist = customJwtTokenInfoRepository.findById(jwtTokenId);

            if (!tokenToBlacklist.isPresent()) {
                log.warn("unable to find customJwtTokenInfo from database, jwtId: {}", jwtTokenId);
                return emptyOkResponse;
            }

            blacklist(tokenToBlacklist.get());

            Map<String, Object> transferredCustomClaims = new HashMap<>();

            if (tokenToBlacklist.get().getCustomClaimSetKeys() != null && !tokenToBlacklist.get().getCustomClaimSetKeys().isEmpty()) {
                tokenToBlacklist.get().getCustomClaimSetKeys().forEach(customClaimKey -> {
                    try {
                        transferredCustomClaims.put(customClaimKey, customJwtToken.getJWTClaimsSet().getClaim(customClaimKey));
                    } catch (ParseException e) {
                        log.error("unable to transfer claim from old token to extended token", e);
                        throw new IllegalStateException(e);
                    }
                });
            }

            int expirationInMinutesCalculatedFromOldJwtToken = (int) (Math.abs(customJwtToken.getJWTClaimsSet().getExpirationTime().getTime() - customJwtToken.getJWTClaimsSet().getIssueTime().getTime()) / 60000L);

            return createCustomJwtToken(
                    new CustomJwtTokenRequest(transferredCustomClaims, expirationInMinutesCalculatedFromOldJwtToken, cookieName),
                    response);
        } catch (ParseException e) {
            log.error("unable to parse JWT from cookie value " + cookie.getValue(), e);
            return emptyOkResponse;
        }
    }

    /**
     *
     * @param cookieName name of cookie containing JWT
     * @param httpServletRequest incoming request
     * @return contains map with keys "JWTCreated" and "JWTExpirationTimestamp" if successful,
     * empty 200 status response otherwise
     */
    @ApiOperation(value = "custom userinfo implementation", response = String.class)
    @ApiResponse(code = 200, response = String.class, message = "Token extended")
    @PostMapping("/custom-jwt-userinfo")
    public ResponseEntity<?> customUserInfo(@RequestBody String cookieName, HttpServletRequest httpServletRequest) {

        Cookie customJwtCookie = getCustomJwtTokenFromRequest(cookieName, httpServletRequest);

        if (customJwtCookie == null) {
            return emptyOkResponse;
        }

        try {
            if ( !jwtUtils.isJwtTokenValid(customJwtCookie.getValue(), true)) {

                log.debug("cookie with value {} is not valid", customJwtCookie.getValue());
                return emptyOkResponse;
            }

            SignedJWT customJwtToken = SignedJWT.parse(customJwtCookie.getValue());


            UUID jwtTokenId = UUID.fromString(customJwtToken.getJWTClaimsSet().getJWTID());
            Optional<CustomJwtTokenInfo> tokenOptional = customJwtTokenInfoRepository.findById(jwtTokenId);


            if (!tokenOptional.isPresent()) {
                return emptyOkResponse;
            }

            CustomJwtTokenInfo customJwtTokenInfo = tokenOptional.get();

            Map<String, Object> resultingJwtMap = new HashMap<>();
            customJwtTokenInfo.getCustomClaimSetKeys().forEach(
                    customClaimKey -> {
                        try {
                            resultingJwtMap.put(customClaimKey, customJwtToken.getJWTClaimsSet().getClaim(customClaimKey));
                        } catch (ParseException e) {
                            log.error("cannot get claim value for key: {}", customClaimKey);
                        }
                    }
            );

            //adding expiration claims
            resultingJwtMap.put("JWTCreated", customJwtToken.getJWTClaimsSet().getIssueTime().getTime());
            resultingJwtMap.put("JWTExpirationTimestamp", customJwtToken.getJWTClaimsSet().getExpirationTime().getTime());

            return ResponseEntity.ok(resultingJwtMap);

        } catch (ParseException e) {
            log.error("unable to get Cookie value");
            return emptyOkResponse;
        }

    }


    private void blacklist(CustomJwtTokenInfo customJwtTokenInfo) {

        customJwtTokenInfo.setBlacklisted(true);
        customJwtTokenInfo.setBlacklistedDate(new Timestamp(System.currentTimeMillis()));

        customJwtTokenInfoRepository.save(customJwtTokenInfo);
        customJwtTokenInfoRepository.flush();
        log.debug("customJwtTokenInfo blacklisted ({})", customJwtTokenInfo);

    }

    private Cookie getCustomJwtTokenFromRequest(@RequestBody String cookieName, HttpServletRequest httpServletRequest) {
        Cookie jwtCookie = null;
        if (httpServletRequest.getCookies() == null || httpServletRequest.getCookies().length == 0) {
            log.warn("no cookies are set");
        } else {

            jwtCookie = Arrays.stream(httpServletRequest.getCookies())
                    .filter(cookie -> cookieName.equals(cookie.getName()) && cookie.getValue() != null)
                    .findFirst()
                    .orElse(null);
        }
        return jwtCookie;
    }

}
