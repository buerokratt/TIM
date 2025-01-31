package ee.eesti.authentication.repository;

import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import jakarta.persistence.EntityManager;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;


class JwtTokenInfoRepositoryTest extends AbstractSpringBasedTest {

    @Autowired
    private JwtTokenInfoRepository repository;

    @Autowired
    private EntityManager entityManager;

    @Test
    void testSavingJwtToDatabase() {
        JwtTokenInfo jwtTokenInfo = new JwtTokenInfo();
        jwtTokenInfo.setExpiredDate(new Timestamp(new Date().getTime() + 42L));
//        jwtTokenInfo.setLegacySessionId("test");

        repository.save(jwtTokenInfo);
        repository.flush();

        entityManager.detach(jwtTokenInfo);

        Optional<JwtTokenInfo> fromDatabase = repository.findById(jwtTokenInfo.getJwtUuid());

        assertTrue(fromDatabase.isPresent());
        assertNotSame(fromDatabase.get(), jwtTokenInfo);
        assertThat(fromDatabase.get(), is(jwtTokenInfo));
    }

    @Test
    void testFindBlacklistedToken() {
        UUID tokenId = UUID.randomUUID();

        JwtTokenInfo jwtTokenInfo = new JwtTokenInfo();
        jwtTokenInfo.setExpiredDate(new Timestamp(new Date().getTime() + 42L));
//        jwtTokenInfo.setLegacySessionId("test");
        jwtTokenInfo.setJwtUuid(tokenId);
        jwtTokenInfo.setBlacklisted(true);

        repository.save(jwtTokenInfo);

        repository.flush();

        assertTrue(repository.findByJwtUuidAndBlacklistedIsTrue(tokenId).isPresent());
    }
}
