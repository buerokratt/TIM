package ee.eesti.authentication.repository;

import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface JwtTokenInfoRepository extends JpaRepository<JwtTokenInfo, UUID> {

	Optional<JwtTokenInfo> findByJwtUuidAndBlacklistedIsTrue(UUID uuid);
}
