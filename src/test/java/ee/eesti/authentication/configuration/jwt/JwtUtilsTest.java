package ee.eesti.authentication.configuration.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


class JwtUtilsTest extends AbstractSpringBasedTest {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;

    @Autowired
    private JwtSignatureConfig jwtSignatureConfig;


    @Test
    void testIsTokenValid() throws Exception {

        UserInfo userInfo = new UserInfo();
        SignedJWT signedJwt = jwtUtils.createSignedJwt(UUID.randomUUID(), userInfo);
        String serializedToken = signedJwt.serialize();
        System.out.println(serializedToken);

        assertTrue(jwtUtils.isJwtTokenValid(serializedToken, false));

        SignedJWT signedJwtFromTestKeystore = getSignedJwtFromTestKeystore(userInfo);

        assertFalse(jwtUtils.isJwtTokenValid(signedJwtFromTestKeystore.serialize(), false));

    }

    private SignedJWT getSignedJwtFromTestKeystore(UserInfo userInfo) throws Exception {
        Date issueDate = userInfo.getLoggedInDate() == null
                ? new Date()
                : userInfo.getLoggedInDate();
        Date expirationDate = userInfo.getLoginExpireDate() == null
                ? DateUtils.addMinutes(issueDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())
                : userInfo.getLoginExpireDate();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),
                new JWTClaimsSet.Builder()
                        .jwtID(UUID.randomUUID().toString())
                        .issuer(jwtUtils.getFirstIssuer())
                        .issueTime(issueDate)
                        .expirationTime(expirationDate)
                        .subject(userInfo.getPersonalCode())
                        .claim("personalCode", userInfo.getPersonalCode())
                        .claim("firstName", userInfo.getFirstName())
                        .claim("lastName", userInfo.getLastName())
                        .build()
        );

        signedJWT.sign(getTestJwtSigner());

        return signedJWT;
    }

    private JWSSigner getTestJwtSigner() throws Exception {

        InputStream inputStream = Files.newInputStream(Paths.get("src", "test", "resources", "test_jwtkeystore.jks"));

        return new RSASSASigner(JwtUtils.getJwtSignKeyFromKeystore("JKS", inputStream, "changeit".toCharArray(), "jwtsign"));

    }
}
