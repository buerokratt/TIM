package ee.eesti.authentication.service;

import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.dao.PortaalDao;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.enums.ChannelType;
import ee.eesti.authentication.enums.Language;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import rig.commons.aop.Timed;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Manages sessions.
 */
@Service
@Slf4j
@Timed
public class SessionsService {

    private final SessionsRepository sessionRepository;

    private final PortaalDao portaalDao;

    private final LegacyPortalIntegrationConfig config;

    public SessionsService(SessionsRepository sessionRepository, PortaalDao portaalDao, LegacyPortalIntegrationConfig config) {
        this.sessionRepository = sessionRepository;
        this.portaalDao = portaalDao;
        this.config = config;
    }

    /**
     * Login. Returns a SessionsEntity containing information about active session.
     * @param user  contains user information
     * @param sessionId session's id
     * @param mobilenumber  mobile number
     * @param userOriginIp ip of user's login
     * @param userLanguage user's language
     * @param userAgentHeader user agent string
     *
     *
     * @throws IllegalArgumentException if user does not have an Estonian personal code
     * @return contains information about sessions
     */
    public SessionsEntity createSessionEntity(UserInfo user,
                                              ChannelType channel,
                                              String sessionId,
                                              String mobilenumber,
                                              String userOriginIp,
                                              String userLanguage,
                                              String userAgentHeader) {

        if (!user.isHasEstonianPersonalCode()) {
            throw new IllegalArgumentException("cannot create entity for not EE resident. PersonalCode: " + user.getPersonalCode());
        }

        SessionsEntity sessionEntity = sessionRepository.findBySessionId(sessionId).orElse(new SessionsEntity());

        LocalDateTime currentTimestamp = LocalDateTime.now();

        String personalCode = user.getPersonalCode().replaceAll("\\D", "");
        sessionEntity.setChannel(channel.getChannel());
        sessionEntity.setSessionId(sessionId);
        sessionEntity.setPersonalCode(personalCode);
        sessionEntity.setAuthenticatedAs(user.getAuthenticatedAs());
        sessionEntity.setHash(user.getHash());
        sessionEntity.setUsername(personalCode);
        sessionEntity.setValidFrom(currentTimestamp);
        sessionEntity.setValidTo(currentTimestamp.plusMinutes(config.getSessionTimeoutMinutes()));
        sessionEntity.setGivenname(user.getFirstName());
        sessionEntity.setSurname(user.getLastName());
        sessionEntity.setMobileNumber(mobilenumber);

        sessionEntity.setParams(String.format("{{LANG, %s},{XMLHTTP,YES}}", userLanguage));

        sessionEntity.setRights(portaalDao.getRights(personalCode));
        sessionEntity.setCreated(currentTimestamp);
        sessionEntity.setLastModified(currentTimestamp);

        sessionEntity.setIp(userOriginIp);
        sessionEntity.setBrowser(userAgentHeader);

        String loginlevel = channel.getLoginLevel();
        sessionEntity.setLoginLevel(loginlevel);

        sessionEntity = sessionRepository.saveAndFlush(sessionEntity);
        log.info("sessionEntity created with id :{}", sessionEntity.getId());

        portaalDao.executeBgLogin(sessionId, user.getPersonalCodeWithoutCountryPrefix());

        return sessionEntity;
    }

    /**
     *
     * @return new UUID, similar to  java.util UUID with the "-" characters removed
     */
    public static String createSessionId() {
        return UUID.randomUUID().toString().toLowerCase().replace("-", "");
    }


    /**
     * Login. Starts a legacy session.
     * @param request incoming request
     * @param user contains user's info
     * @param channel enumerated selection of possible channels
     * @param mobileNumber mobile number
     * @return  contains information about session
     */
    public SessionsEntity openLegacyPortalLoginSession(HttpServletRequest request, UserInfo user, ChannelType channel,
                                                       String mobileNumber) {
        String userOriginIp = "";
        String languageCode = Language.EE.name().toLowerCase();

        if (request.getSession(false) != null) {
            userOriginIp = (String) request.getSession(false).getAttribute(config.getRequestIpAttribute());
            languageCode = Language.getByUri((String) request.getSession(false).getAttribute(config.getRedirectUrlAttribute())).name().toLowerCase();
        } else {
            log.warn("session for given request not found");
        }

        String sessionId = getSessionIdFromRequestOrGenerateNewOne(request);

        return createSessionEntity(
                user,
                channel,
                sessionId,
                mobileNumber,
                userOriginIp,
                languageCode,
                request.getHeader("User-Agent"));
    }

    private String getSessionIdFromRequestOrGenerateNewOne(HttpServletRequest request) {
        String sessionId = null;

        if (request.getCookies() != null) {
            // check if the session cookie is already set on the client's browser.
            // system will use that for creating the sessionID

            // Due to legacy portal behaviour there could be several cookies with the same name
            // but only one of them is active.
            List<String> sessionIds = Arrays.stream(request.getCookies())
                    .filter(cookie ->
                            config.getSessionCookieName().equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .toList();

            // Search for the active cookie using database query
            if (!sessionIds.isEmpty()) {
                List<SessionsEntity> validSessions = sessionRepository.findAllBySessionIdInAndValidToAfter(
                        sessionIds,
                        LocalDateTime.now());
                if (validSessions.size() == 1) {
                    sessionId = validSessions.get(0).getSessionId();
                } else if (validSessions.size() > 1) {
                    log.warn("there are more than one active session cookies for a single client");
                }
            }
        }

        if (sessionId == null) {
            // no session cookie set. Most probably the user has came from some API endpoint
            sessionId = createSessionId();
        }
        return sessionId;
    }

    /**
     * @return all sessions
     */
    public List<SessionsEntity> getSessionIds() {
        return sessionRepository.findAll();
    }


}
