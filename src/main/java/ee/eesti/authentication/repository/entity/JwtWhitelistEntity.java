package ee.eesti.authentication.repository.entity;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.sql.Timestamp;

@EqualsAndHashCode(of = "jwtHash")
@Data
@Entity
@Table(name = "whitelist", schema = "jwt_whitelist")
public class JwtWhitelistEntity {
    @Id
    @Column(name = "jwt_hash", nullable = false)
    private String jwtHash;

    @Column(name = "expiration_date", nullable = false)
    private Timestamp expirationDate;

}
