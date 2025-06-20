package app.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Test web configuration for web-related beans and settings.
 */
@TestConfiguration
@EnableWebMvc
@ActiveProfiles("test")
public class TestWebConfig implements WebMvcConfigurer {
    // Web-related configurations can be added here
}
