package ee.eesti.authentication.repository;

import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.repository.entity.JwtWhitelistEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WhitelistRepositoryTest extends AbstractSpringBasedTest {

    @Autowired
    private WhitelistRepository repository;

    @BeforeEach
    void cleanUp() {
        repository.deleteAll();
    }

    @Test
    void findByJwtHashFindsSavedEntity() {
        JwtWhitelistEntity entity = new JwtWhitelistEntity();
        entity.setJwtHash("hash-1");
        entity.setExpirationDate(Timestamp.valueOf(LocalDateTime.now().plusMinutes(30)));
        repository.save(entity);

        Optional<JwtWhitelistEntity> found = repository.findByJwtHash("hash-1");

        assertTrue(found.isPresent());
        assertEquals("hash-1", found.get().getJwtHash());
    }

    @Test
    void findByJwtHashReturnsEmptyWhenNotFound() {
        assertFalse(repository.findByJwtHash("missing").isPresent());
    }

    @Test
    void findByExpirationDateBeforeReturnsOnlyExpiredEntries() {
        JwtWhitelistEntity expired = new JwtWhitelistEntity();
        expired.setJwtHash("expired-hash");
        expired.setExpirationDate(Timestamp.valueOf(LocalDateTime.now().minusMinutes(5)));
        repository.save(expired);

        JwtWhitelistEntity notExpired = new JwtWhitelistEntity();
        notExpired.setJwtHash("valid-hash");
        notExpired.setExpirationDate(Timestamp.valueOf(LocalDateTime.now().plusMinutes(30)));
        repository.save(notExpired);

        List<JwtWhitelistEntity> results = repository.findByExpirationDateBefore(LocalDateTime.now());

        assertEquals(1, results.size());
        assertEquals("expired-hash", results.get(0).getJwtHash());
    }
}
