package ee.eesti.authentication.enums;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ChannelTypeTest {

    @Test
    void getByAmrFindsExactMatch() {
        assertEquals(ChannelType.M_ID, ChannelType.getByAmr("mID"));
        assertEquals(ChannelType.ID, ChannelType.getByAmr("idcard"));
        assertEquals(ChannelType.PANK, ChannelType.getByAmr("banklink"));
        assertEquals(ChannelType.EIDAS, ChannelType.getByAmr("eIDAS"));
        assertEquals(ChannelType.SMARTID, ChannelType.getByAmr("smartid"));
        assertEquals(ChannelType.DEFAULT, ChannelType.getByAmr("default"));
    }

    @Test
    void getByAmrReturnsNullForUnknownValue() {
        assertNull(ChannelType.getByAmr("something-unknown"));
        assertNull(ChannelType.getByAmr(null));
    }

    @Test
    void getByChannelFindsExactMatch() {
        assertEquals(ChannelType.AUTENTIMATA, ChannelType.getByChannel("AUTENTIMATA"));
        assertEquals(ChannelType.ID, ChannelType.getByChannel("ID"));
        assertEquals(ChannelType.M_ID, ChannelType.getByChannel("M-ID"));
        assertEquals(ChannelType.PANK, ChannelType.getByChannel("PANK"));
        assertEquals(ChannelType.EIDAS, ChannelType.getByChannel("eIDAS"));
        assertEquals(ChannelType.SMARTID, ChannelType.getByChannel("SMARTID"));
    }

    @Test
    void getByChannelReturnsNullForUnknownValue() {
        assertNull(ChannelType.getByChannel("something-unknown"));
        assertNull(ChannelType.getByChannel(null));
    }

    @Test
    void loginLevelAndAmrAreExposedPerChannel() {
        assertEquals("40", ChannelType.ID.getLoginLevel());
        assertEquals("idcard", ChannelType.ID.getAmr());
        assertEquals("20", ChannelType.AUTENTIMATA.getLoginLevel());
        assertEquals("", ChannelType.AUTENTIMATA.getAmr());
    }
}
