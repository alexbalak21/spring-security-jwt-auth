package app.controller;

import app.config.TestSecurityConfig;
import app.config.TestWebConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(HomeController.class)
@Import({TestSecurityConfig.class, TestWebConfig.class})
@ActiveProfiles("test")
class HomeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtDecoder jwtDecoder;
    
    @BeforeEach
    void setUp() {
        // Setup default JWT decoding behavior for tests
        Jwt jwt = createTestJwt("testuser", List.of("read"));
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);
    }
    
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_ISSUER = "http://localhost:0"; // Should match issuer-uri in application-test.yml
    
    private Jwt createTestJwt(String subject, List<String> scopes) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .header("typ", "JWT")
                .header("kid", "test-key-1")
                .claim("sub", subject)
                .claim("scope", String.join(" ", scopes))
                .claim("iss", TEST_ISSUER)
                .claim("aud", "jwt-audience-test")
                .claim("jti", "test-jti")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(3600))
                .build();
    }
    
    @Test
    void contextLoads() {
        // This test will pass if the application context loads successfully
    }

    @Test
    void publicEndpoint_ShouldBeAccessibleWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/public"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is a public endpoint. No authentication required."));
    }

    @Test
    void home_WithValidJwtToken_ShouldReturnUserInfo() throws Exception {
        // Arrange
        String username = "jwtuser";
        Jwt jwt = createTestJwt(username, List.of("read", "write"));
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);
        
        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer test-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.message").isString())
                .andExpect(jsonPath("$.authorities").isArray())
                .andExpect(jsonPath("$.authorities[0]").value("SCOPE_read"))
                .andExpect(jsonPath("$.authorities[1]").value("SCOPE_write"))
                .andExpect(jsonPath("$.token_issuer").value(TEST_ISSUER));
    }

    @Test
    void home_WithInvalidJwtToken_ShouldReturnUnauthorized() throws Exception {
        // Arrange - simulate invalid token
        when(jwtDecoder.decode(anyString())).thenThrow(new RuntimeException("Invalid token"));
        
        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }
    
    @Test
    void home_WithoutAuthentication_ShouldReturnUnauthorized() throws Exception {
        // The security configuration requires authentication for all endpoints except /public/**
        // and we're not providing any authentication in this test
        mockMvc.perform(get("/"))
                .andExpect(status().isUnauthorized());
    }
    
    @Test
    void testSecurityConfiguration() {
        // This test will pass if the security configuration is properly set up
    }
}
