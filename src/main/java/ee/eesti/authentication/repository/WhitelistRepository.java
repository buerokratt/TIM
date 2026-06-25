package ee.eesti.authentication.repository;

import ee.eesti.authentication.repository.entity.JwtWhitelistEntity;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface WhitelistRepository extends JpaRepository<JwtWhitelistEntity, Long> {

  Optional<JwtWhitelistEntity> findByJwtHash(String jwt_hash);

  List<JwtWhitelistEntity> findByExpirationDateBefore(LocalDateTime now);

/*  @Query("SELECT j FROM JwtWhitelist j WHERE j.jwtHash IN :jwtHashes AND j.expirationDate > :now")
  List<JwtWhitelistEntity> findUnexpiredJwtHashes(Set<String> jwtHashes, LocalDateTime now);
*/
}
