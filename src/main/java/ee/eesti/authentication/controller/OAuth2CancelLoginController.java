package ee.eesti.authentication.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import rig.commons.aop.Timed;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This controller has just one endpoint that will cause a redirect to main page
 */
@Controller
@Slf4j
@Timed
public class OAuth2CancelLoginController {


    @Value("${frontpage.redirect.url}")
    private String frontPageRedirectUrl;

    /**
     * Will redirect user to main page (redirect url defined in private variable of controller)
     * @param response incoming response
     * @throws IOException
     */
    @GetMapping("/cancel-auth")
    public void processCancelAuthorization(HttpServletResponse response) throws IOException {
        log.debug("user canceled authentication");
        response.sendRedirect(frontPageRedirectUrl);
    }

}
