package app.controller;

import app.config.TestSecurityConfig;
import app.config.TestWebConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(HomeController.class)
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
@ExtendWith({SpringExtension.class, MockitoExtension.class})
@AutoConfigureMockMvc(addFilters = true)
class HomeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtDecoder jwtDecoder;

    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_ISSUER = "http://localhost:0";
    private static final String TEST_TOKEN = "test-token";

    @BeforeEach
    void setUp() {
        try {
            // Setup default JWT decoding behavior for tests
            Jwt jwt = createTestJwt(TEST_USERNAME, List.of("read"));
            when(jwtDecoder.decode(anyString())).thenReturn(jwt);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set up test JWT", e);
        }
    }

    private Jwt createTestJwt(String subject, List<String> scopes) {
        Instant now = Instant.now();
        return Jwt.withTokenValue(TEST_TOKEN)
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
    void publicEndpoint_ShouldBeAccessibleWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/public"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andExpect(content().string("This is a public endpoint. No authentication required."));
    }

    @ParameterizedTest
    @MethodSource("provideScopesForHomeEndpoint")
    void home_WithValidJwtToken_ShouldReturnUserInfo(List<String> scopes, int expectedStatus) throws Exception {
        // Arrange
        Jwt jwt = createTestJwt(TEST_USERNAME, scopes);
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);

        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(TEST_USERNAME))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.authorities").isArray())
                .andExpect(jsonPath("$.token_issuer").exists())
                .andExpect(jsonPath("$.token_issued_at").exists())
                .andExpect(jsonPath("$.token_expires_at").exists());
    }

    private static Stream<Arguments> provideScopesForHomeEndpoint() {
        return Stream.of(
                Arguments.of(List.of("read"), 200),
                Arguments.of(List.of("write"), 200),
                Arguments.of(List.of("read", "write"), 200)
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidScenarios")
    void home_WithDifferentScenarios_ShouldReturnExpectedStatus(String testName, List<String> scopes, int expectedStatus) throws Exception {
        // Arrange
        Jwt jwt = createTestJwt(TEST_USERNAME, scopes);
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);

        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer " + TEST_TOKEN))
                .andExpect(status().is(expectedStatus));
    }

    private static Stream<Arguments> provideInvalidScenarios() {
        return Stream.of(
                Arguments.of("No scopes", List.of(), 403),
                Arguments.of("Invalid scope", List.of("invalid"), 403)
        );
    }

    @Test
    void home_WithInvalidJwtToken_ShouldReturnUnauthorized() throws Exception {
        // Arrange - simulate invalid token
        when(jwtDecoder.decode(anyString()))
            .thenThrow(new RuntimeException("Invalid token"));
        
        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
    }

    @Test
    void home_WithoutAuthentication_ShouldReturnUnauthorized() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
    }

    @Test
    void home_WithExpiredJwt_ShouldReturnUnauthorized() throws Exception {
        // Arrange - simulate expired JWT
        when(jwtDecoder.decode(anyString()))
            .thenThrow(new RuntimeException("JWT expired"));
        
        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer expired-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
    }
    
    @Test
    void home_WithNoScopes_ShouldReturnForbidden() throws Exception {
        // Arrange - JWT with no scopes
        Jwt jwt = createTestJwt(TEST_USERNAME, List.of());
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);
        
        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer no-scope-token"))
                .andExpect(status().isForbidden());
    }
    
    @Test
    void home_WithValidTokenAndReadScope_ShouldReturnUserInfo() throws Exception {
        // Arrange
        Jwt jwt = createTestJwt(TEST_USERNAME, List.of("read"));
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);
        
        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(TEST_USERNAME))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.authorities").isArray())
                .andExpect(jsonPath("$.token_issuer").exists())
                .andExpect(jsonPath("$.token_issued_at").exists())
                .andExpect(jsonPath("$.token_expires_at").exists());
    }
}
