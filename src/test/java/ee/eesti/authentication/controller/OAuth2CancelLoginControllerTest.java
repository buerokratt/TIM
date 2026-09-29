package ee.eesti.authentication.controller;

import ee.eesti.AbstractSpringBasedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class OAuth2CancelLoginControllerTest extends AbstractSpringBasedTest {

    @Autowired
    private MockMvc mvc;

    @Value("${frontpage.redirect.url}")
    private String frontPageRedirectUrl;

    @Test
    void cancelAuthRedirectsToFrontPage() throws Exception {
        mvc.perform(get("/cancel-auth"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(frontPageRedirectUrl));
    }
}
