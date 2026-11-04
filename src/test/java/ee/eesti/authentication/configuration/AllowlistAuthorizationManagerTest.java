package ee.eesti.authentication.configuration;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AllowlistAuthorizationManagerTest {

    @Test
    void allowsAddressResolvedFromHostName() {
        assertTrue(new AllowlistAuthorizationManager("localhost").isAllowed("127.0.0.1"));
    }

    @Test
    void deniesAddressNotMatchingHostName() {
        assertFalse(new AllowlistAuthorizationManager("localhost").isAllowed("10.0.0.5"));
    }

    @Test
    void unresolvableHostNameDoesNotBlockOtherEntries() {
        AllowlistAuthorizationManager manager =
                new AllowlistAuthorizationManager("ruuter.invalid,127.0.0.1");

        assertTrue(manager.isAllowed("127.0.0.1"));
        assertFalse(manager.isAllowed("10.0.0.5"));
    }

    @Test
    void matchesAddressesRangesAndIpv6() {
        AllowlistAuthorizationManager manager =
                new AllowlistAuthorizationManager("127.0.0.1, 172.16.0.0/12, ::1");

        assertTrue(manager.isAllowed("127.0.0.1"));
        assertTrue(manager.isAllowed("172.18.0.4"));
        assertTrue(manager.isAllowed("0:0:0:0:0:0:0:1"));
        assertFalse(manager.isAllowed("192.168.0.1"));
    }
}
