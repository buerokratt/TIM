package ee.eesti.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.eesti.AbstractSpringBasedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SessionKeyControllerTest extends AbstractSpringBasedTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void addedKeyIsFoundByCheck() throws Exception {
        SessionKeyController.SessionKeyRequest request = new SessionKeyController.SessionKeyRequest("session-key-1", 30L);

        mvc.perform(post("/sessionkey/add")
                        .content(objectMapper.writeValueAsString(request))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mvc.perform(post("/sessionkey/check")
                        .content(objectMapper.writeValueAsString(request))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    void checkingUnknownKeyReturnsNotFound() throws Exception {
        SessionKeyController.SessionKeyRequest request = new SessionKeyController.SessionKeyRequest("unknown-key", 30L);

        mvc.perform(post("/sessionkey/check")
                        .content(objectMapper.writeValueAsString(request))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());
    }

    @Test
    void keysEndpointReturnsOnlyKeysThatAreNotWhitelisted() throws Exception {
        SessionKeyController.SessionKeyRequest whitelisted = new SessionKeyController.SessionKeyRequest("whitelisted-key", 30L);
        mvc.perform(post("/sessionkey/add")
                        .content(objectMapper.writeValueAsString(whitelisted))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        List<SessionKeyController.SessionKeyRequest> keysToCheck = List.of(
                whitelisted,
                new SessionKeyController.SessionKeyRequest("not-whitelisted-key", 30L));

        mvc.perform(post("/sessionkey/keys")
                        .content(objectMapper.writeValueAsString(keysToCheck))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().json("[\"not-whitelisted-key\"]"));
    }

    @Test
    void keysStringEndpointReturnsOnlyKeysThatAreNotWhitelisted() throws Exception {
        SessionKeyController.SessionKeyRequest whitelisted = new SessionKeyController.SessionKeyRequest("whitelisted-key-2", 30L);
        mvc.perform(post("/sessionkey/add")
                        .content(objectMapper.writeValueAsString(whitelisted))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mvc.perform(post("/sessionkey/keysString")
                        .content("whitelisted-key-2,not-whitelisted-key-2"))
                .andExpect(status().isOk())
                .andExpect(content().json("[\"not-whitelisted-key-2\"]"));
    }

    // Uses a UUID-shaped key: WhiteListService.delete() -> blacklist() calls UUID.fromString(sessionKey)
    // with no try/catch around it, so a non-UUID key would throw, get swallowed by the global
    // RestExceptionHandler (returns 200 for any exception), and the entry would silently survive -
    // a real behavior quirk, not something to route around by asserting the wrong thing.
    @Test
    void deleteRemovesKeyFromWhitelist() throws Exception {
        SessionKeyController.SessionKeyRequest request =
                new SessionKeyController.SessionKeyRequest(UUID.randomUUID().toString(), 30L);

        mvc.perform(post("/sessionkey/add")
                        .content(objectMapper.writeValueAsString(request))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mvc.perform(post("/sessionkey/delete")
                        .content(objectMapper.writeValueAsString(request))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        mvc.perform(post("/sessionkey/check")
                        .content(objectMapper.writeValueAsString(request))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());
    }

    @Test
    void deletingUnknownKeyReturnsNotFound() throws Exception {
        SessionKeyController.SessionKeyRequest request =
                new SessionKeyController.SessionKeyRequest(UUID.randomUUID().toString(), 30L);

        mvc.perform(post("/sessionkey/delete")
                        .content(objectMapper.writeValueAsString(request))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());
    }
}
