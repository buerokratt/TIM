package ee.eesti.authentication.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class CustomErrorControllerTest {

    @Test
    void whitelabelErrorReturnsEmptyOkResponse() {
        ResponseEntity<?> response = new CustomErrorController().whitelabelError();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNull(response.getBody(), "no internal error details should be exposed");
    }
}
