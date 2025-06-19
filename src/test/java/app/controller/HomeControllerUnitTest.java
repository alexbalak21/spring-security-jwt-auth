package app.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class HomeControllerUnitTest {

    @InjectMocks
    private HomeController homeController;

    @Mock
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void publicEndpoint_ShouldReturnPublicMessage() {
        String result = homeController.publicEndpoint();
        assertEquals("This is a public endpoint. No authentication required.", result);
    }

    @Test
    void home_WithAuthentication_ShouldReturnUserInfo() {
        // Arrange
        Jwt jwt = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .claim("sub", "testuser")
                .claim("scope", "read write")
                .claim("iss", "http://test-issuer")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(authentication.getPrincipal()).thenReturn(jwt);
        List<SimpleGrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("SCOPE_read"),
                new SimpleGrantedAuthority("SCOPE_write")
        );
        when(authentication.getAuthorities()).thenAnswer(invocation -> authorities);

        // Act
        Map<String, Object> result = homeController.home(null, authentication);

        // Assert
        assertNotNull(result);
        assertEquals("testuser", result.get("username"));
        assertTrue(((List<?>) result.get("authorities")).contains("SCOPE_read"));
        assertTrue(((List<?>) result.get("authorities")).contains("SCOPE_write"));
        assertEquals("http://test-issuer", result.get("token_issuer"));
    }

    @Test
    void home_WithoutAuthentication_ShouldReturnAnonymousUser() {
        // Act
        Map<String, Object> result = homeController.home(() -> "anonymous", null);

        // Assert
        assertNotNull(result);
        assertEquals("anonymous", result.get("username"));
        assertTrue(((List<?>) result.get("authorities")).isEmpty());
    }
}
