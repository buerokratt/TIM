package ee.eesti.authentication.enums;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LanguageTest {

    @Test
    void getUriReturnsAssociatedUri() {
        assertEquals("/est/", Language.EE.getUri());
        assertEquals("/eng/", Language.EN.getUri());
        assertEquals("/rus/", Language.RU.getUri());
    }

    @Test
    void getByUriMatchesOnSubstring() {
        assertEquals(Language.EN, Language.getByUri("https://www.arendus.eesti.ee/eng/portal"));
        assertEquals(Language.RU, Language.getByUri("https://www.arendus.eesti.ee/rus/"));
        assertEquals(Language.EE, Language.getByUri("https://www.arendus.eesti.ee/est/"));
    }

    @Test
    void getByUriDefaultsToEstonianWhenNullOrUnmatched() {
        assertEquals(Language.EE, Language.getByUri(null));
        assertEquals(Language.EE, Language.getByUri("https://www.arendus.eesti.ee/"));
    }
}
