package ee.eesti.authentication.repository.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import jakarta.persistence.*;
import java.sql.Timestamp;
import java.util.Date;
import java.util.UUID;

/**
 * A mapped superclass for entities related to jwt.
 */
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@MappedSuperclass
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
public abstract class GenericJwtTokenInfo {

    @Id
    @Column(name = "jwt_uuid", nullable = false)
    @Builder.Default
    private UUID jwtUuid = UUID.randomUUID();

    @Column(name = "expiration_date", nullable = false)
    private Timestamp expiredDate;

    @Column(name = "issued_date", nullable = false)
    @Builder.Default
    private Timestamp issuedDate = Timestamp.from(new Date().toInstant());

    @Column(name = "is_blacklisted")
    private boolean blacklisted;

    @Column(name = "blacklisted_date")
    private Timestamp blacklistedDate;

}
