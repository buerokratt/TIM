package ee.eesti.authentication.configuration;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import rig.commons.handlers.GenericHeaderLogHandler;
import rig.commons.handlers.LogHandler;

import java.util.List;

/**
 * Used to add rest controller handlers
 */
@Configuration
public class RestConfiguration implements WebMvcConfigurer {

    /**
     * generates unique ID for request and loads it to dynamic context
     */
    private final LogHandler handler = LogHandler.builder().build();

    @Value("${userIPLoggingPrefix:from ip}")
    private String loggingPrefix;
    @Value("${userIPHeaderName:x-forwarded-for}")
    private final String headerName = "";
    @Value("${userIPLoggingMDCkey:userIP}")
    private final String key = "userIP";

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        GenericHeaderLogHandler ipHeaderHandler = GenericHeaderLogHandler.builder().key(key).messagePrefix(loggingPrefix).headerName(headerName).build();
        registry.addInterceptor(ipHeaderHandler);
        registry.addInterceptor(handler);
    }

    // Boot 4 defaults to Jackson 3 for JSON responses; domain classes like UserInfo still use
    // Jackson 2 annotations (e.g. @JsonSerialize on DateToTimestampConverter), so a Jackson 2
    // converter has to be registered explicitly and take priority over Boot's default.
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        // Drop Boot 4's default Jackson 3 JSON converter(s) and add a Jackson 2 one last, so
        // plain-String/byte-array responses (e.g. JwtController's PEM key download) still get
        // picked up by the earlier String/byte-array converters, and only actual POJOs - which
        // nothing earlier in the list can write - fall through to JSON.
        converters.removeIf(converter -> converter.getSupportedMediaTypes().contains(MediaType.APPLICATION_JSON));
        converters.add(new MappingJackson2HttpMessageConverter(objectMapper()));
    }
}
