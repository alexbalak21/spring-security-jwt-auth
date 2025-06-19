package app.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;

import java.security.interfaces.RSAPublicKey;

@TestConfiguration
@ActiveProfiles("test")
public class TestWebConfig {
    
    @Bean
    public JwtDecoder jwtDecoder() {
        // Return a mock JwtDecoder that always throws an exception
        return token -> {
            throw new RuntimeException("JwtDecoder not implemented in test");
        };
    }
    
    @Bean
    public RSAPublicKey rsaPublicKey() {
        // Return null since we're mocking JwtDecoder
        return null;
    }
}
