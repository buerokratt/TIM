package ee.eesti.authentication.configuration.jwt;

/**
 * Result of checking a JWT.
 */
public enum JwtTokenStatus {
    /** signature, claims and dates are fine and the token is not blacklisted */
    VALID,
    /** token is valid, but has been flagged ("greylisted") to be refreshed by its holder */
    UPDATE_REQUIRED,
    /** token is malformed, has a bad signature, is expired, issued in the future or blacklisted */
    INVALID;

    public boolean isValid() {
        return this != INVALID;
    }
}
