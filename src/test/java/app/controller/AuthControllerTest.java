package app.controller;

import app.config.TestRsaKeyConfig;
import app.dto.LoginRequest;
import app.service.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import(TestRsaKeyConfig.class)
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private TokenService tokenService;

    @Test
    void login_WithValidCredentials_ReturnsToken() throws Exception {
        // Arrange
        String username = "testuser";
        String password = "password";
        String token = "test.jwt.token";

        Authentication auth = new UsernamePasswordAuthenticationToken(username, password);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(auth);
        when(tokenService.generateToken(any(Authentication.class)))
                .thenReturn(token);

        LoginRequest loginRequest = new LoginRequest(username, password);

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(result -> System.out.println("Response: " + result.getResponse().getContentAsString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value(token))
                .andExpect(jsonPath("$.type").value("Bearer"));
                
        // Verify interactions
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(tokenService).generateToken(any(Authentication.class));
    }

    @Test
    void login_WithInvalidCredentials_ReturnsUnauthorized() throws Exception {
        // Arrange
        String username = "wronguser";
        String password = "wrongpass";
        
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        LoginRequest loginRequest = new LoginRequest(username, password);

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Authentication failed: Bad credentials"));
                
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verifyNoInteractions(tokenService);
    }

    @Test
    void login_WithMissingUsername_ReturnsBadRequest() throws Exception {
        // Arrange
        String password = "password";
        
        // Missing username
        String requestBody = "{\"password\":\"" + password + "\"}";

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Username is required")));
                
        verifyNoInteractions(authenticationManager, tokenService);
    }
    
    @Test
    void login_WithMissingPassword_ReturnsBadRequest() throws Exception {
        // Arrange
        String username = "testuser";
        
        // Missing password
        String requestBody = "{\"username\":\"" + username + "\"}";

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Password is required")));
                
        verifyNoInteractions(authenticationManager, tokenService);
    }
    
    @Test
    void login_WithEmptyBody_ReturnsBadRequest() throws Exception {
        // Act & Assert - Empty body
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Username is required")))
                .andExpect(jsonPath("$.message").value(containsString("Password is required")));
                
        verifyNoInteractions(authenticationManager, tokenService);
    }
    
    @Test
    void login_WithInvalidJson_ReturnsBadRequest() throws Exception {
        // Act & Assert - Invalid JSON
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{invalid json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").isNotEmpty());
                
        verifyNoInteractions(authenticationManager, tokenService);
    }
    
    @Test
    void login_WithEmptyUsernameAndPassword_ReturnsBadRequest() throws Exception {
        // Arrange
        LoginRequest loginRequest = new LoginRequest("", "");
        
        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Username is required")))
                .andExpect(jsonPath("$.message").value(containsString("Password is required")));
                
        verifyNoInteractions(authenticationManager, tokenService);
    }
    
    @Test
    void login_WithWhitespaceUsername_ReturnsBadRequest() throws Exception {
        // Arrange
        LoginRequest loginRequest = new LoginRequest("   ", "password");
        
        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Username is required")));
                
        verifyNoInteractions(authenticationManager, tokenService);
    }
    
    @Test
    void login_WithVeryLongUsername_ReturnsBadRequest() throws Exception {
        // Arrange
        String veryLongUsername = "a".repeat(256); // Exceeds typical 255 char limit
        LoginRequest loginRequest = new LoginRequest(veryLongUsername, "password");
        
        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"));
                
        verifyNoInteractions(authenticationManager, tokenService);
    }
    
    @Test
    void login_WithTokenGenerationFailure_ReturnsInternalServerError() throws Exception {
        // Arrange
        String username = "testuser";
        String password = "password";
        
        Authentication auth = new UsernamePasswordAuthenticationToken(username, password);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(auth);
        when(tokenService.generateToken(any(Authentication.class)))
                .thenThrow(new RuntimeException("Token generation failed"));

        LoginRequest loginRequest = new LoginRequest(username, password);

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Internal Server Error"))
                .andExpect(jsonPath("$.message").value(containsString("Token generation failed")));
                
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(tokenService).generateToken(auth);
    }
    
    @Test
    void login_WithAccountLocked_ReturnsUnauthorized() throws Exception {
        // Arrange
        String username = "lockeduser";
        String password = "password";
        
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new LockedException("Account is locked"));

        LoginRequest loginRequest = new LoginRequest(username, password);

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value(containsString("Account is locked")));
                
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verifyNoInteractions(tokenService);
    }
    
    @Test
    void login_WithAccountDisabled_ReturnsUnauthorized() throws Exception {
        // Arrange
        String username = "disableduser";
        String password = "password";
        
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new DisabledException("Account is disabled"));

        LoginRequest loginRequest = new LoginRequest(username, password);

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value(containsString("Account is disabled")));
                
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verifyNoInteractions(tokenService);
    }
    
    @Test
    void login_WithWrongContentType_ReturnsUnsupportedMediaType() throws Exception {
        // Arrange
        String username = "testuser";
        String password = "password";
        
        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.TEXT_PLAIN)
                .content("username=" + username + "&password=" + password))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.error").value("Unsupported Media Type"));
                
        verifyNoInteractions(authenticationManager, tokenService);
    }
}
