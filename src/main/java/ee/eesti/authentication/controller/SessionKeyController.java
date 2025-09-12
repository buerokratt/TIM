package ee.eesti.authentication.controller;

import ee.eesti.authentication.service.WhiteListService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rig.commons.aop.Timed;

import java.sql.Timestamp;

import static java.time.LocalDateTime.now;

@CrossOrigin(originPatterns = "*", allowCredentials = "true")
@RestController
@RequestMapping("/sessionkey")
@Slf4j
@Timed
public class SessionKeyController {

    private final WhiteListService allowList;

    private static final ResponseEntity<?> emptyOkResponse = ResponseEntity.ok().build();
    private static final ResponseEntity<?> emptyNotFoundResponse = ResponseEntity.notFound().build();

    public SessionKeyController(WhiteListService allowList) {
        this.allowList = allowList;
    }

    @Value("${sessionkey.whitelist.period:30}")
    private Long sessionKeyTimeout;

    public record SessionKeyRequest (String sessionKey, Long sessionLength) {};

    @PostMapping("/add")
    public ResponseEntity<?> addSessionKey(@RequestBody SessionKeyRequest request, HttpServletResponse response) {
        Long len = request.sessionLength != null ? request.sessionLength : sessionKeyTimeout;
        String key = request.sessionKey;
        boolean success = allowList.addSessionToAllowlist(key, Timestamp.valueOf(now().plusMinutes(len)));
        log.debug("Added key '%s' for %d minutes.".formatted(key, len));
        if (!success) {
            log.error("Failed to add session key '%s' (%d minutes)".formatted(key, len));
        }
        return emptyOkResponse;
    }

    @PostMapping("/check")
    public ResponseEntity<?> checkSessionKey(@RequestBody SessionKeyRequest request, HttpServletResponse response) {
        if (allowList.checkWhitelisted(request.sessionKey))
            return emptyOkResponse;
        else
            return emptyNotFoundResponse;
    }
}
