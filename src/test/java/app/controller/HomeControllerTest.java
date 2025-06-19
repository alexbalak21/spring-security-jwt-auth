package app.controller;

import app.config.TestSecurityConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.time.Instant;

import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(HomeController.class)
@ActiveProfiles("test")
@Import(TestSecurityConfig.class)
class HomeControllerTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private JwtDecoder jwtDecoder;

    @BeforeEach
    void setup() {
        // No setup needed as MockMvc is auto-configured by @WebMvcTest
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
                .andExpect(jsonPath("$.authorities", hasItem("ROLE_USER")));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void home_WithAdminRole_ShouldReturnAdminInfo() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.authorities", hasItem("ROLE_ADMIN")));
    }

    @Test
    void home_WithoutAuthentication_ShouldReturnUnauthorized() throws Exception {
        // Our TestSecurityConfig requires authentication for "/"
        mockMvc.perform(get("/"))
                .andExpect(status().isUnauthorized());
    }
    
    @Test
    void publicEndpoint_ShouldBeAccessibleWithoutAuthentication() throws Exception {
        // Public endpoint should be accessible without authentication
        mockMvc.perform(get("/public"))
                .andExpect(status().isOk())
                .andExpect(content().string("This is a public endpoint. No authentication required."));
    }

    @Test
    void home_WithJwtToken_ShouldReturnTokenDetails() throws Exception {
        // Arrange
        String username = "jwtuser";
        String issuer = "test-issuer";
        String scope = "read write";
        
        // Setup JWT token
        Jwt jwt = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .claim("scope", scope)
                .subject(username)
                .issuer(issuer)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
                
        when(jwtDecoder.decode("test-token")).thenReturn(jwt);
        
        // Act & Assert
        mockMvc.perform(get("/")
                .header("Authorization", "Bearer test-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.token_issuer").value(issuer))
                .andExpect(jsonPath("$.authorities").isArray());
    }
    
    @Test
    @WithMockUser(username = "testuser")
    void home_WithMockUser_ShouldNotContainTokenDetails() throws Exception {
        // Act & Assert - When using @WithMockUser, no JWT token is present
        mockMvc.perform(MockMvcRequestBuilders.get("/"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_issuer").doesNotExist())
                .andExpect(jsonPath("$.token_issued_at").doesNotExist())
                .andExpect(jsonPath("$.token_expires_at").doesNotExist());
    }
}
