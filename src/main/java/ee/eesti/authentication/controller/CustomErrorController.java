package ee.eesti.authentication.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rig.commons.aop.Timed;

@Slf4j
@RestController
@Timed
public class CustomErrorController implements ErrorController {

    /**
     * @return empty OK response to ensure no information about internal errors is shown
     */
    @RequestMapping(value = "/error")
    public ResponseEntity<?> whitelabelError() {
        log.warn("Whitelabel error page accessed.");
        return ResponseEntity.ok().build();
    }
}
