package ee.eesti.authentication.repository.entity;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity containing session's info.
 * Entity is associated with "sessions" table.
 */
@NamedQuery(name = "SessionsEntity.isSessionExists",
        query = "SELECT count(*) > 1 FROM SessionsEntity s WHERE s.sessionId=:sessionId")
@Entity
@Table(schema = "pwa", name = "sessions")
@SequenceGenerator(name = "sessions_sess_id_seq",
        sequenceName = "pwa.sessions_sess_id_seq", allocationSize = 1)
@Data
public class SessionsEntity {

    @Id
    @Column(name = "sess_id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE,
            generator = "sessions_sess_id_seq")
    private Long id;

    @Column(name = "channel")
    private String channel;

    @Column(name = "session_id")
    private String sessionId;

    @Column(name = "personal_code")
    private String personalCode;

    @Column(name = "authenticated_as")
    private String authenticatedAs;

    @Column(name = "hash")
    private String hash;

    @Column(name = "valid_from")
    private LocalDateTime validFrom;

    @Column(name = "valid_to")
    private LocalDateTime validTo;

    @Column(name = "givenname")
    private String givenname;

    @Column(name = "surname")
    private String surname;

    @Column(name = "params")
    private String params;

    @Column(name = "rights")
    private String rights;

    @Column(name = "created")
    private LocalDateTime created;

    @Column(name = "last_modified")
    private LocalDateTime lastModified;

    @Column(name = "ip")
    private String ip;

    @Column(name = "browser")
    private String browser;

    @Column(name = "username")
    private String username;

    @Column(name = "loginlevel")
    private String loginLevel;

    @Column(name = "mobile_number")
    private String mobileNumber;

    @Column(name = "certificate_type")
    private String certificateType;

}
