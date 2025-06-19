package app.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;

import java.security.interfaces.RSAPublicKey;

@TestConfiguration
@ActiveProfiles("test")
public class TestConfig {
    
    @Bean
    public JwtDecoder jwtDecoder() throws Exception {
        // Return a mock JwtDecoder to avoid loading real keys during context initialization
        return token -> null;
    }
    
    @Bean
    public RSAPublicKey rsaPublicKey() {
        // Return a mock public key to avoid loading from file during context initialization
        return null;
    }
}
