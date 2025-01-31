package ee.eesti.authentication.repository.entity;

import lombok.Getter;
import lombok.Setter;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Entity contains info about (custom)jwt token.
 * Entity is associated with "custom_jwt_token" table
 */
@Entity
@Table(name = "custom_jwt_token", schema = "jwt_blacklist")
@Getter
@Setter
public class CustomJwtTokenInfo extends GenericJwtTokenInfo {

    public static final String CLAIMS_KEYS_SEPARATOR = "::_::";

    @Column(name = "custom_claim_keys", columnDefinition = "text")
    private String customClaimKeys;

    public void setCustomClaimKeysFromSet(Set<String> claimsKeys) {
        if (claimsKeys != null && !claimsKeys.isEmpty()) {
            customClaimKeys = String.join(CLAIMS_KEYS_SEPARATOR, claimsKeys);
        } else {
            customClaimKeys = null;
        }
    }

    public Set<String> getCustomClaimSetKeys() {
        if (customClaimKeys == null) {
            return Collections.emptySet();
        }

        return new HashSet<>(Arrays.asList(customClaimKeys.split(CLAIMS_KEYS_SEPARATOR)));
    }

}
