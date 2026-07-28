package ee.eesti.authentication.handlers;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

// Pins down current behavior: RestExceptionHandler catches every Throwable application-wide and always
// responds 200 OK with no body, regardless of what actually went wrong (validation errors, DB errors,
// NPEs, ...). That's a deliberate design choice for not leaking internal error details, but it also means
// a genuine 4xx/5xx-worthy failure looks identical to success at the HTTP level - worth having pinned
// down explicitly so any future change to this behavior is a visible, deliberate test update.
class RestExceptionHandlerTest {

    @Test
    void anyExceptionIsHandledAsAnEmptyOkResponse() {
        RestExceptionHandler handler = new RestExceptionHandler();

        assertAlwaysOk(handler, new RuntimeException("boom"));
        assertAlwaysOk(handler, new IllegalArgumentException("invalid"));
        assertAlwaysOk(handler, new NullPointerException());
    }

    private void assertAlwaysOk(RestExceptionHandler handler, Exception exception) {
        ResponseEntity<Object> response = handler.doHandle(exception);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNull(response.getBody());
    }
}
