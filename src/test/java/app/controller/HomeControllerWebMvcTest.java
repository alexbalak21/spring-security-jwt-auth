package app.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.springframework.security.test.context.support.WithMockUser;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class HomeControllerWebMvcTest {

    private static final String TEST_TOKEN = "test-token";
    private static final String TEST_ISSUER = "http://test-issuer";
    private static final String TEST_SUBJECT = "testuser";

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @MockBean
    private JwtDecoder jwtDecoder;
    
    @BeforeEach
    void setup() {
        // Setup MockMvc with Spring Security
        this.mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }
    
    private Jwt createJwt(String... scopes) {
        return Jwt.withTokenValue(TEST_TOKEN)
                .header("alg", "RS256")
                .header("typ", "JWT")
                .claim("sub", TEST_SUBJECT)
                .claim("scope", String.join(" ", scopes))
                .claim("iss", TEST_ISSUER)
                .issuedAt(Instant.now().minusSeconds(60))
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
    }



    @Test
    void publicEndpoint_ShouldBeAccessibleWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/public"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is a public endpoint. No authentication required."));
    }

    @Test
    void homeEndpoint_WithValidJwt_ShouldReturnWelcomeMessage() throws Exception {
        // Given
        Jwt validJwt = createJwt("read", "write");
        when(jwtDecoder.decode(anyString())).thenReturn(validJwt);

        // When/Then
        mockMvc.perform(get("/")
                        .header("Authorization", "Bearer " + TEST_TOKEN)
                        .contentType("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Welcome to the protected resource!"))
                .andExpect(jsonPath("$.username").value(TEST_SUBJECT))
                .andExpect(jsonPath("$.authorities").isArray())
                .andExpect(jsonPath("$.token_issuer").value(TEST_ISSUER));
    }

    @Test
    void homeEndpoint_WithInvalidJwt_ShouldReturnUnauthorized() throws Exception {
        // Given
        when(jwtDecoder.decode(anyString()))
                .thenThrow(new JwtException("Invalid JWT token"));

        // When/Then
        mockMvc.perform(get("/")
                        .header("Authorization", "Bearer invalid-token")
                        .contentType("application/json"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Invalid JWT token"));
    }

    @Test
    void homeEndpoint_WithoutJwt_ShouldReturnUnauthorized() throws Exception {
        // When/Then
        mockMvc.perform(get("/")
                        .contentType("application/json"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").isString());
    }

    @Test
    void homeEndpoint_WithExpiredJwt_ShouldReturnUnauthorized() throws Exception {
        // Given
        String expiredMessage = "JWT expired at " + Instant.now().minusSeconds(3600);
        when(jwtDecoder.decode(anyString()))
                .thenThrow(new JwtException(expiredMessage));

        // When/Then
        mockMvc.perform(get("/")
                        .header("Authorization", "Bearer expired-token")
                        .contentType("application/json"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value(expiredMessage));
    }

    @Test
    void homeEndpoint_WithMissingRequiredScope_ShouldReturnForbidden() throws Exception {
        // Given - Create a JWT with no scopes
        Jwt jwtWithoutScopes = createJwt("");
        when(jwtDecoder.decode(anyString())).thenReturn(jwtWithoutScopes);

        // When/Then
        mockMvc.perform(get("/")
                        .header("Authorization", "Bearer " + TEST_TOKEN))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Forbidden"))
                .andExpect(jsonPath("$.message").value(containsString("Access Denied")));
    }
}