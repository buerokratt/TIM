package ee.eesti.authentication.configuration;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import rig.commons.handlers.GenericHeaderLogHandler;
import rig.commons.handlers.LogHandler;

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
}
