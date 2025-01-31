package ee.eesti.authentication.configuration.jwt;


import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.repository.CustomJwtTokenInfoRepository;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;
import java.util.function.Supplier;

@Component
@Slf4j
public class JwtUtils {

    private final LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;
    private final JwtSignatureConfig jwtSignatureConfig;
    private final JWSSigner rsassaSigner;
    private final JWSVerifier verifier;
    private final JwtTokenInfoRepository jwtTokenInfoRepository;
    private final CustomJwtTokenInfoRepository customJwtTokenInfoRepository;
    @Value("${jwt-integration.signature.secureCookie:true}")
    private boolean secureCookie;

    public JwtUtils(LegacyPortalIntegrationConfig legacyPortalIntegrationConfig,
                    JwtSignatureConfig jwtSignatureConfig,
                    JWSSigner rsassaSigner,
                    JWSVerifier verifier,
                    JwtTokenInfoRepository jwtTokenInfoRepository,
                    CustomJwtTokenInfoRepository customJwtTokenInfoRepository) {
        this.legacyPortalIntegrationConfig = legacyPortalIntegrationConfig;
        this.jwtSignatureConfig = jwtSignatureConfig;
        this.rsassaSigner = rsassaSigner;
        this.verifier = verifier;
        this.jwtTokenInfoRepository = jwtTokenInfoRepository;
        this.customJwtTokenInfoRepository = customJwtTokenInfoRepository;
    }

    /**
     * The claims "personalCode", "firstName" and "lastName" of the returned token
     * are filled from UserInfo
     *
     * @param jwtTokenId id for token
     * @param userInfo information about user
     * @return filled with information from userInfo
     */
    public SignedJWT createSignedJwt(UUID jwtTokenId, UserInfo userInfo) {
        Date issueDate = userInfo.getLoggedInDate() == null
                ? new Date()
                : userInfo.getLoggedInDate();
        Date expirationDate = userInfo.getLoginExpireDate() == null
            ? DateUtils.addMinutes(issueDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())
            : userInfo.getLoginExpireDate();

        Map<String, Object> claims = new HashMap<>();
        claims.put("personalCode", userInfo.getPersonalCode());
        claims.put("authenticatedAs", userInfo.getAuthenticatedAs());
        claims.put("hash", userInfo.getHash());
        claims.put("firstName", userInfo.getFirstName());
        claims.put("lastName", userInfo.getLastName());
        claims.put("authMethod", userInfo.getAuthMethod());

        return getSignedJWTWithClaims(jwtTokenId, userInfo.getPersonalCode(), claims, issueDate, expirationDate);
    }

    /**
     *
     * @param jwtTokenId token id
     * @param subject  subject
     * @param claims map of claims
     * @param issueDate issue Date
     * @param expirationDate expiration Date
     * @return token filled with appropriate information from the input parameters
     */
    public SignedJWT getSignedJWTWithClaims(UUID jwtTokenId, String subject, Map<String, Object> claims, Date issueDate, Date expirationDate) {

        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .jwtID(jwtTokenId.toString())
                .issuer(getFirstIssuer())
                .issueTime(issueDate)
                .expirationTime(expirationDate)
                .subject(subject);
        if (claims != null) {
            claims.forEach(claimsSetBuilder::claim);
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                claimsSetBuilder.build());

        try {
            signedJWT.sign(rsassaSigner);
        } catch (JOSEException e) {
            log.error("cannot sign the JWT token", e);
            throw new IllegalStateException(e);
        }

        return signedJWT;
    }

    /**
     * Serializes the token into the cookie
     * @param signedJWT token to put into cookie
     * @return cookie containing token information
     */
    public Cookie getJwtCookie(SignedJWT signedJWT) {
        Cookie jwtCookie = new Cookie(jwtSignatureConfig.getCookieName(), signedJWT.serialize());
        jwtCookie.setDomain(legacyPortalIntegrationConfig.getSessionCookieDomain());
        jwtCookie.setSecure(secureCookie);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setPath("/");
        return jwtCookie;
    }


    /**
     * Creates cookie containing session ID or finds such a cookie from the request if such already exists.
     * The cookie name and domain are defined in LegacyPortalIntegrationConfig
     *
     * @param request incoming request
     * @param sessionsEntity session entity
     * @param alwaysCreateCookie always create new cookie even if request already contains one
     * @return cookie containing session ID
     *
     * @see  LegacyPortalIntegrationConfig
     *
     */
    public Cookie getLegacySessionCookie(HttpServletRequest request, SessionsEntity sessionsEntity, boolean alwaysCreateCookie) {

        Supplier<Cookie> cookieSupplier = () -> {
            Cookie sessionCookie = new Cookie(removeNewlines(legacyPortalIntegrationConfig.getSessionCookieName()),
                    removeNewlines(sessionsEntity.getSessionId()));
            sessionCookie.setHttpOnly(true);
            sessionCookie.setSecure(secureCookie);
            sessionCookie.setPath("/");
            sessionCookie.setDomain(removeNewlines(legacyPortalIntegrationConfig.getSessionCookieDomain()));
            return sessionCookie;
        };

        if (request == null || request.getCookies() == null || alwaysCreateCookie) {
            return cookieSupplier.get();
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> legacyPortalIntegrationConfig.getSessionCookieName().equals(cookie.getName()))
                .findFirst()
                .orElseGet(cookieSupplier);
    }


    /**
     *
     * @param cookie cookie containing users info
     * @return users info returned from cookie
     */
    public UserInfo decodeJwtTokenFromCookie(Cookie cookie) {

        if (cookie == null || cookie.getValue() == null) {
            return null;
        }

        return getUserInfo(cookie.getValue());
    }

    private UserInfo getUserInfo(String jwtString) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtString);
            String personalCode = (String) signedJWT.getJWTClaimsSet().getClaim("personalCode");
            String authenticatedAs = (String) signedJWT.getJWTClaimsSet().getClaim("authenticatedAs");
            String hash = (String) signedJWT.getJWTClaimsSet().getClaim("hash");
            String firstName = (String) signedJWT.getJWTClaimsSet().getClaim("firstName");
            String lastName = (String) signedJWT.getJWTClaimsSet().getClaim("lastName");
            String authMethod = (String) signedJWT.getJWTClaimsSet().getClaim("authMethod");

            return new UserInfo(
                    personalCode,
                    authenticatedAs,
                    hash,
                    firstName,
                    lastName,
                    signedJWT.getJWTClaimsSet().getIssueTime(),
                    signedJWT.getJWTClaimsSet().getExpirationTime(),
                    authMethod);

        } catch (ParseException e) {
            log.warn("could not parse UserInfo from JWT token string", e);
        }
        return null;
    }

    /**
     *
     * @param jwtTokenToCheck token to check
     * @param isCustomJwtToken is it a CustomJwtToken
     * @return true if it was a valid token
     *
     * @see ee.eesti.authentication.repository.entity.CustomJwtTokenInfo
     */

    public boolean isJwtTokenValid(String jwtTokenToCheck, boolean isCustomJwtToken) {
        boolean valid;
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtTokenToCheck);
            valid = signedJWT.verify(verifier);

            Date now = new Date();

            if (signedJWT.getJWTClaimsSet().getJWTID() == null
                    || signedJWT.getJWTClaimsSet().getExpirationTime() == null
                    || signedJWT.getJWTClaimsSet().getIssueTime() == null
                    || !containsIssuer(signedJWT.getJWTClaimsSet().getIssuer())
                    ) {
                log.warn("some attributes of the JWT token (id:{}) are invalid", signedJWT.getJWTClaimsSet().getJWTID());
                valid = false;
            }

            if (now.after(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                log.debug("token (id: {}), is expired", signedJWT.getJWTClaimsSet().getJWTID());
                valid = false;
            } else if (now.before(signedJWT.getJWTClaimsSet().getIssueTime())) {
                log.warn("token (id: {}), issue time is in the future", signedJWT.getJWTClaimsSet().getJWTID());
                valid = false;
            } else {
                //check if the token is blacklisted already
                UUID uuid = UUID.fromString(signedJWT.getJWTClaimsSet().getJWTID());
                boolean blacklisted =
                        isCustomJwtToken
                                ? customJwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(uuid).isPresent()
                                : jwtTokenInfoRepository.findByJwtUuidAndBlacklistedIsTrue(uuid).isPresent();
                log.debug("token with id: {} is blacklisted: {}", signedJWT.getJWTClaimsSet().getJWTID(), blacklisted);
                valid = valid && !blacklisted;
            }

        } catch (Exception e) {
            log.warn("token cannot be verified", e);
            valid = false;
        }

        return valid;
    }

    public static RSAKey getJwtSignKeyFromKeystore(String keyStoreType, InputStream keystoreInputStream, char[] keystorePassword, String keyAlias) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore jwtSignKeyStore = KeyStore.getInstance(keyStoreType);
        jwtSignKeyStore.load(keystoreInputStream, keystorePassword);

        JWKSet jwkSet = JWKSet.load(jwtSignKeyStore, name -> keystorePassword);
        return (RSAKey) jwkSet.getKeyByKeyId(keyAlias);
    }

    public static String removeNewlines(String in) {
        return in.replaceAll("[\n\r]+"," ");
    }

    public String getFirstIssuer() {
        return jwtSignatureConfig.getIssuer().split(",")[0];
    }

    public boolean containsIssuer(String tokenIssuer) {
        return Set.of(jwtSignatureConfig.getIssuer().split(",")).contains(tokenIssuer);
    }

}
