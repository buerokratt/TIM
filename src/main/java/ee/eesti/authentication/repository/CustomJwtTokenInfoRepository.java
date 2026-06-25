package ee.eesti.authentication.repository;

import ee.eesti.authentication.repository.entity.CustomJwtTokenInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CustomJwtTokenInfoRepository extends JpaRepository<CustomJwtTokenInfo, UUID> {

    Optional<CustomJwtTokenInfo> findByJwtUuidAndBlacklistedIsTrue(UUID uuid);

    Optional<CustomJwtTokenInfo> findByJwtUuid(UUID uuid);
}
