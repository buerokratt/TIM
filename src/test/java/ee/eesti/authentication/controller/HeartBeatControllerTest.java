package ee.eesti.authentication.controller;

import ee.eesti.AbstractSpringBasedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class HeartBeatControllerTest extends AbstractSpringBasedTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void healthzReturnsServerAndPackageInfo() throws Exception {
        mvc.perform(get(HeartBeatController.URL))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.appStartTime").exists())
                .andExpect(jsonPath("$.serverTime").exists());
    }
}
