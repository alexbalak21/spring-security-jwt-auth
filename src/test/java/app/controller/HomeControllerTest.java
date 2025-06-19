package app.controller;

import app.config.TestSecurityConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(HomeController.class)
@ActiveProfiles("test")
@Import(TestSecurityConfig.class)
class HomeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtDecoder jwtDecoder;
    
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_ROLE = "USER";
    
    private Jwt createTestJwt(String subject, List<String> scopes) {
        Instant now = Instant.now();
        return new Jwt(
            "test-token",
            now,
            now.plus(1, ChronoUnit.HOURS),
            Map.of("alg", "RS256"),
            Map.of(
                "sub", subject,
                "scope", String.join(" ", scopes),
                "iss", "test-issuer"
            )
        );
    }

    @BeforeEach
    void setUp() {
        // Setup default JWT decoding behavior for tests
        Jwt jwt = createTestJwt(TEST_USERNAME, List.of("read"));
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);
    }

    @Test
    void publicEndpoint_ShouldBeAccessibleWithoutAuthentication() throws Exception {
        // Act & Assert
        mockMvc.perform(MockMvcRequestBuilders.get("/public"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is a public endpoint. No authentication required."));
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"USER"})
    void home_WithMockUser_ShouldReturnUserInfo() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.message").isString())
                .andExpect(jsonPath("$.authorities").isArray())
                .andExpect(jsonPath("$.authorities[0]").value("ROLE_USER"));
    }

    @Test
    void home_WithJwtToken_ShouldReturnTokenDetails() throws Exception {
        // Arrange
        String username = "jwtuser";
        Jwt jwt = createTestJwt(username, List.of("read", "write"));
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);
        
        // Act & Assert
        mockMvc.perform(MockMvcRequestBuilders.get("/")
                .header("Authorization", "Bearer test-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.token_issuer").value("test-issuer"))
                .andExpect(jsonPath("$.authorities").isArray())
                .andExpect(jsonPath("$.authorities[0]").value("SCOPE_read"))
                .andExpect(jsonPath("$.authorities[1]").value("SCOPE_write"));
    }
    
    @Test
    void home_WithoutAuthentication_ShouldReturnUnauthorized() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/"))
                .andExpect(status().isUnauthorized());
    }
}
