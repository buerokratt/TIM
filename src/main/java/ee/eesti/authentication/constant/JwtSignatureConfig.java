package ee.eesti.authentication.constant;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

/**
 * properties relating to jwt. string from @ConfigurationProperties is used as prefix in properties files.
 * Field names as properties names in properties files.
 */
@ConfigurationProperties("jwt-integration.signature")
@Data
@Component
public class JwtSignatureConfig {

    private Resource keyStore;
    private String keyStorePassword;
    private String keyStoreType;
    private String keyAlias;
    private String issuer;

    private String cookieName;

    /**
     * Name of the session id claim in JWTs issued/read by TIM (regular and custom). Tokens are stored with
     * this claim's value so they can be blacklisted / flagged as update required per session.
     */
    private String sidClaim = "sid";

}
