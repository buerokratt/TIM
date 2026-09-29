package ee.eesti.authentication.dao;

import ee.eesti.AbstractSpringBasedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PortaalDaoTest extends AbstractSpringBasedTest {

    @Autowired
    private PortaalDao portaalDao;

    @Test
    @Transactional
    void getRightsReturnsRightsStringFromPortalDb() {
        String rights = portaalDao.getRights("EE38833883383");

        assertTrue(rights.contains("AMETNIK"));
    }

    @Test
    @Transactional
    void executeBgLoginDoesNotThrow() {
        assertDoesNotThrow(() -> portaalDao.executeBgLogin("session-id", "EE38833883383"));
    }
}
