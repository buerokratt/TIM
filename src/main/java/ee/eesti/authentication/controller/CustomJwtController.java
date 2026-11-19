package ee.eesti.authentication.controller;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.configuration.jwt.JwtTokenStatus;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.CustomJwtTokenRequest;
import ee.eesti.authentication.repository.CustomJwtTokenInfoRepository;
import ee.eesti.authentication.repository.entity.CustomJwtTokenInfo;
import ee.eesti.authentication.service.JwtTokenInfoService;
import ee.eesti.authentication.service.WhiteListService;
import io.swagger.annotations.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rig.commons.aop.Timed;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
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

    private final WhiteListService allowList;

    private final JwtTokenInfoService jwtService;

    private final ObjectMapper objectMapper;

    public CustomJwtController(JwtUtils jwtUtils,
                               CustomJwtTokenInfoRepository customJwtTokenInfoRepository,
                               LegacyPortalIntegrationConfig legacyPortalIntegrationConfig,
                               WhiteListService allowListService,
                               JwtTokenInfoService jwtService,
                               ObjectMapper objectMapper) {
        this.jwtUtils = jwtUtils;
        this.customJwtTokenInfoRepository = customJwtTokenInfoRepository;
        this.legacyPortalIntegrationConfig = legacyPortalIntegrationConfig;
        this.allowList = allowListService;
        this.jwtService = jwtService;
        this.objectMapper = objectMapper;
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
        return issueCustomJwtToken(request, false, response);
    }

    private ResponseEntity<?> issueCustomJwtToken(CustomJwtTokenRequest request, boolean updateRequired, HttpServletResponse response) {

        SignedJWT signedJWT = getCustomJwtSigned(request);

        CustomJwtTokenInfo customJwtTokenInfo = new CustomJwtTokenInfo();
        if (updateRequired) {
            customJwtTokenInfo.setUpdateRequired(true);
            customJwtTokenInfo.setUpdateRequiredDate(new Timestamp(System.currentTimeMillis()));
        }

        if (request.getContent() != null) {
            customJwtTokenInfo.setCustomClaimKeysFromSet(request.getContent().keySet());
            Object sid = request.getContent().get(jwtUtils.getSidClaim());
            if (sid != null) {
                customJwtTokenInfo.setSid(sid.toString());
            }
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

        Cookie cookie = new Cookie(JwtUtils.removeNewlines(request.getJwtName()), JwtUtils.removeNewlines(signedJWT.serialize()));
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookie);
        cookie.setDomain(JwtUtils.removeNewlines(legacyPortalIntegrationConfig.getSessionCookieDomain()));

        response.addCookie(cookie);

        Map<String, Object> resultingJwtToken = new HashMap<>();
        resultingJwtToken.put("token", signedJWT.serialize());

        allowList.addSessionToAllowlist(customJwtTokenInfo.getJwtUuid().toString(),
                customJwtTokenInfo.getExpiredDate());

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
     * @return 200 if JWT is valid, 403 if it is valid but flagged as update required,
     * 401 if it is missing or not valid
     */
    @ApiOperation(value = "Verify custom valid JWT token ", response = String.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, response = String.class, message = "Token verified"),
            @ApiResponse(code = 401, message = "Token missing or not valid"),
            @ApiResponse(code = 403, message = "Token valid, but must be updated")
    })
    @PostMapping("/custom-jwt-verify")
    public ResponseEntity<?> verifyCustomJwtToken(@RequestBody String cookieName, HttpServletRequest httpServletRequest) {
        log.debug("verify custom jwt token called for cookieName: {}", cookieName);

        Cookie jwtCookie = getCustomJwtTokenFromRequest(cookieName, httpServletRequest);

        if (jwtCookie == null) {
            log.warn("requested cookie with name '{}' not found or empty", cookieName);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        JwtTokenStatus status = jwtUtils.getJwtTokenStatus(jwtCookie.getValue(), true);

        log.debug("token in cookieName {} status: {}", cookieName, status);

        return switch (status) {
            case VALID -> emptyOkResponse;
            case UPDATE_REQUIRED -> ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            case INVALID -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        };
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
                jwtService.blacklist(tokenToBlacklist.get());
            }
            return emptyOkResponse;

        } catch (Exception e) {
            log.error("failed to blacklist JWT token: " + cookie.getValue(), e);
            return emptyOkResponse;
        }
    }


    /**
     * Flags the custom JWT in cookie {@code cookieName} as update required ("greylisted").
     * The token stays valid, but custom-jwt-verify answers 403 for it until it is extended.
     *
     * @param cookieName name of cookie containing JWT
     * @param httpServletRequest incoming request
     * @return response status 200 regardless if flagging succeeded or not
     */
    @ApiOperation(value = "Flag custom JWT token as update required", response = String.class)
    @ApiResponse(code = 200, response = String.class, message = "Token flagged")
    @PostMapping("/custom-jwt-update-required")
    public ResponseEntity<?> markCustomJwtTokenUpdateRequired(@RequestBody String cookieName, HttpServletRequest httpServletRequest) {

        Cookie cookie = getCustomJwtTokenFromRequest(cookieName, httpServletRequest);

        if (cookie == null) {
            return emptyOkResponse;
        }

        try {
            SignedJWT jwt = SignedJWT.parse(cookie.getValue());
            Optional<CustomJwtTokenInfo> token = customJwtTokenInfoRepository.findById(UUID.fromString(jwt.getJWTClaimsSet().getJWTID()));

            if (token.isEmpty()) {
                log.warn("token to be flagged update required not found JWT: {}", jwt.serialize());
            } else if (!token.get().isBlacklisted()) {
                jwtService.markUpdateRequired(token.get());
            }
        } catch (Exception e) {
            log.error("failed to flag JWT token update required: " + cookie.getValue(), e);
        }
        return emptyOkResponse;
    }

    /**
     * Flags all non-blacklisted custom JWTs whose session id claim matches the given value as update required.
     *
     * @param sid session id (plain-text body) whose tokens are to be flagged
     * @return 200 with the number of flagged tokens, 400 if sid is missing
     */
    @ApiOperation(value = "Flag all custom JWTs with the given sid claim as update required", response = ResponseEntity.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, response = ResponseEntity.class, message = "tokens flagged, body contains the count"),
            @ApiResponse(code = 400, message = "sid missing")
    })
    @PostMapping("/custom-jwt-update-required-sid")
    public ResponseEntity<?> markCustomJwtTokensUpdateRequiredBySid(
            @ApiParam(name = "sid", value = "Session id (session id claim value) whose tokens to flag")
            @RequestBody(required = false) String sid) {
        if (sid == null || sid.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        int count = jwtService.markUpdateRequiredBySid(sid.trim());
        return ResponseEntity.ok(Map.of("updateRequired", count));
    }

    /**
     * Replaces a valid custom JWT with a new one. Accepts two body formats:
     * <ul>
     *     <li>JSON object - same as for custom-jwt-generate. The current JWT is read from the cookie named by
     *     {@code JWTName}; the new JWT is built from the given {@code content} and {@code expirationInMinutes}.</li>
     *     <li>plain text (legacy) - the cookie name. The new JWT carries over the custom claims of the current JWT,
     *     its update-required flag, and gets the same lifetime it was originally issued with.</li>
     * </ul>
     * In both cases the current JWT is blacklisted.
     *
     * @param body JSON {@link CustomJwtTokenRequest} or plain-text cookie name
     * @param httpServletRequest incoming request
     * @param response current response
     * @return contains new token if valid token was found in input otherwise
     * an empty 200 response is returned
     */
    @ApiOperation(value = "extend custom valid JWT token ", response = String.class)
    @ApiResponse(code = 200, response = String.class, message = "Token extended")
    @PostMapping("/custom-jwt-extend")
    public ResponseEntity<?> extendCustomJwtToken(@RequestBody String body,
                                                  HttpServletRequest httpServletRequest,
                                                  HttpServletResponse response) {

        CustomJwtTokenRequest extendRequest = null;
        JsonNode jsonBody = parseJsonOrNull(body);

        if (jsonBody != null && jsonBody.isObject()) {
            try {
                extendRequest = objectMapper.treeToValue(jsonBody, CustomJwtTokenRequest.class);
            } catch (JsonProcessingException e) {
                log.warn("invalid custom jwt extend request: {}", e.getOriginalMessage());
                return emptyOkResponse;
            }
            if (extendRequest.getJwtName() == null || extendRequest.getJwtName().isBlank()
                    || extendRequest.getExpirationInMinutes() < 1) {
                log.warn("invalid custom jwt extend request, JWTName and expirationInMinutes >= 1 are required");
                return emptyOkResponse;
            }
        }

        String cookieName = extendRequest != null ? extendRequest.getJwtName() : body;
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

            if (tokenToBlacklist.isEmpty()) {
                log.warn("unable to find customJwtTokenInfo from database, jwtId: {}", jwtTokenId);
                return emptyOkResponse;
            }

            jwtService.blacklist(tokenToBlacklist.get());

            if (extendRequest == null) {
                // legacy extend copies the old (possibly stale) claims, so an update-required flag must carry over
                return issueCustomJwtToken(
                        requestFromExistingToken(customJwtToken, tokenToBlacklist.get(), cookieName),
                        tokenToBlacklist.get().isUpdateRequired(),
                        response);
            }

            return issueCustomJwtToken(extendRequest, false, response);
        } catch (ParseException e) {
            log.error("unable to parse JWT from cookie value " + cookie.getValue(), e);
            return emptyOkResponse;
        }
    }

    private JsonNode parseJsonOrNull(String body) {
        try {
            return objectMapper.readTree(body);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /**
     * Legacy extend: rebuild the request from the existing token's custom claims and original lifetime.
     */
    private CustomJwtTokenRequest requestFromExistingToken(SignedJWT customJwtToken,
                                                          CustomJwtTokenInfo tokenInfo,
                                                          String cookieName) throws ParseException {
        Map<String, Object> transferredCustomClaims = new HashMap<>();

        if (tokenInfo.getCustomClaimSetKeys() != null) {
            for (String customClaimKey : tokenInfo.getCustomClaimSetKeys()) {
                transferredCustomClaims.put(customClaimKey, customJwtToken.getJWTClaimsSet().getClaim(customClaimKey));
            }
        }

        int expirationInMinutes = (int) (Math.abs(customJwtToken.getJWTClaimsSet().getExpirationTime().getTime()
                - customJwtToken.getJWTClaimsSet().getIssueTime().getTime()) / 60000L);

        return new CustomJwtTokenRequest(transferredCustomClaims, expirationInMinutes, cookieName);
    }

    /**
     *
     * @param cookieName name of cookie containing JWT
     * @param httpServletRequest incoming request
     * @return contains map with keys "JWTCreated", "JWTExpirationTimestamp" and "JWTUpdateRequired" if successful,
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
            resultingJwtMap.put("JWTUpdateRequired", customJwtTokenInfo.isUpdateRequired());

            return ResponseEntity.ok(resultingJwtMap);

        } catch (ParseException e) {
            log.error("unable to get Cookie value");
            return emptyOkResponse;
        }

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

    private void blacklistExpired() {

    }


}
