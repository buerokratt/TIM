package ee.eesti.authentication.service;

import ee.eesti.authentication.repository.CustomJwtTokenInfoRepository;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.WhitelistRepository;
import ee.eesti.authentication.repository.entity.CustomJwtTokenInfo;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import ee.eesti.authentication.repository.entity.JwtWhitelistEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
public class WhiteListService {

    private final WhitelistRepository repository;
    private final CustomJwtTokenInfoRepository customJwts;
    private final JwtTokenInfoRepository jwts;
    private final JwtTokenInfoService jwtService;

    public WhiteListService(WhitelistRepository repository, CustomJwtTokenInfoRepository customJwts, JwtTokenInfoRepository jwts, JwtTokenInfoService jwtService) {
        this.repository = repository;
        this.customJwts = customJwts;
        this.jwts = jwts;
        this.jwtService = jwtService;
    }

    public boolean addSessionToAllowlist(String sessionHash, Timestamp expiredAt) {
        JwtWhitelistEntity entity = repository.findByJwtHash(sessionHash)
                .orElse(new JwtWhitelistEntity());
        entity.setJwtHash(sessionHash);
        entity.setExpirationDate(expiredAt);
        entity = repository.saveAndFlush(entity);
        log.debug("{} added to whitelist", entity.getJwtHash());
        return true;
    }

    private void blacklist(String id) {
        UUID uuid = UUID.fromString(id);
        try {
            JwtTokenInfo jwt = jwts.getReferenceById(uuid);
            jwtService.blacklist(jwt);
        } catch(Exception ex) {}

        try {
            CustomJwtTokenInfo cjwt = customJwts.getReferenceById(uuid);
            jwtService.blacklist(cjwt);
        } catch (Exception ex) {}
    }

    @Scheduled(fixedDelayString = "${jwt.whitelist.period:30000}")
    public void scheduleBlacklisting() {
        List<JwtWhitelistEntity> whitelistEntities = repository.findByExpirationDateBefore(LocalDateTime.now());

        log.debug("in whitelist:" +
                whitelistEntities.stream().map(
                        e -> "%s (%s)".formatted( e.getJwtHash(), e.getExpirationDate().toString())
                ).collect(Collectors.joining(",")));

        whitelistEntities.forEach(
                entity -> {
                    blacklist(entity.getJwtHash());
                    repository.delete(entity);
                    log.debug("Blacklisted {}", entity);
                }
        );

        log.trace("JWT blacklisting update tick");
    }

    public boolean checkWhitelisted(String id) {
        Optional<JwtWhitelistEntity> entity = repository.findByJwtHash(id);
        if (entity.isPresent())
            log.debug("Found %s".formatted(entity.get().getJwtHash()));
        else
            log.debug("ID %s not found".formatted(id));
        return entity.isPresent();
    }

    public boolean delete(String sessionKey) {
        Optional<JwtWhitelistEntity> session = repository.findByJwtHash(sessionKey);

        if (session.isEmpty())
            return false;

        blacklist(session.get().getJwtHash());
        repository.delete(session.get());

        return true;
    }
}
