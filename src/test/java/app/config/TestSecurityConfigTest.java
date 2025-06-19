package app.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

@SpringJUnitConfig(TestSecurityConfig.class)
@ActiveProfiles("test")
class TestSecurityConfigTest {

    @Autowired
    private JwtDecoder jwtDecoder;
    
    @Autowired
    private JwtEncoder jwtEncoder;

    @Test
    void jwtEncoderAndDecoder_ShouldWorkTogether() throws Exception {
        // Create JWT claims
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://test-issuer.com")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(3600))
                .subject("test-user")
                .claim("scope", "read write")
                .build();
                
        // Encode the JWT
        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        assertNotNull(token, "Token should not be null");
        
        // Decode the JWT
        Jwt decodedJwt = jwtDecoder.decode(token);
        
        // Verify the decoded JWT
        assertNotNull(decodedJwt, "Decoded JWT should not be null");
        assertEquals("test-user", decodedJwt.getSubject(), "Subject should match");
        assertEquals("https://test-issuer.com", decodedJwt.getIssuer().toString(), "Issuer should match");
        assertTrue(decodedJwt.getExpiresAt().isAfter(now), "Expiration should be in the future");
    }
    
    @Test
    void jwtDecoder_ShouldBeConfigured() {
        assertNotNull(jwtDecoder, "JwtDecoder should be configured");
    }
    
    @Test
    void jwtEncoder_ShouldBeConfigured() {
        assertNotNull(jwtEncoder, "JwtEncoder should be configured");
    }
}
