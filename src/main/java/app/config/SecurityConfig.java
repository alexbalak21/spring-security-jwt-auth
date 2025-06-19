package app.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.core.AuthenticationException;
import org.springframework.http.MediaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.HashMap;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Main security configuration class for the application.
 * Configures JWT authentication, authorization, and security filters.
 */
@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);
    private static final String LOG_PREFIX = "[SecurityConfig] ";

    private final RsaKeyProperties rsaKeyProperties;

    public SecurityConfig(RsaKeyProperties rsaKeyProperties) {
        this.rsaKeyProperties = rsaKeyProperties;
        log.info("{}Initializing SecurityConfig with RSA key properties", LOG_PREFIX);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        log.info("{}Configuring in-memory user details service", LOG_PREFIX);
        try {
            var user = User.withUsername("alex")
                    .password("{noop}password") // {noop} for demo only - use proper password encoding in production
                    .authorities("read")
                    .roles("USER")
                    .build();

            log.debug("{}Created in-memory user: {}", LOG_PREFIX, user.getUsername());
            return new InMemoryUserDetailsManager(user);
        } catch (Exception e) {
            log.error("{}Failed to configure user details service", LOG_PREFIX, e);
            throw e;
        }
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        log.info("{}Configuring AuthenticationManager", LOG_PREFIX);
        try {
            AuthenticationManager manager = new ProviderManager(authenticationProvider());
            log.debug("{}Successfully created AuthenticationManager", LOG_PREFIX);
            return manager;
        } catch (Exception e) {
            log.error("{}Failed to create AuthenticationManager", LOG_PREFIX, e);
            throw e;
        }
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        log.info("{}Configuring DaoAuthenticationProvider", LOG_PREFIX);
        try {
            DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
            authProvider.setUserDetailsService(userDetailsService());
            // WARNING: Using NoOpPasswordEncoder for demo purposes only
            // In production, use a proper password encoder like BCryptPasswordEncoder
            authProvider.setPasswordEncoder(
                    org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance()
            );
            log.debug("{}Configured DaoAuthenticationProvider with user details service and password encoder", LOG_PREFIX);
            return authProvider;
        } catch (Exception e) {
            log.error("{}Failed to configure DaoAuthenticationProvider", LOG_PREFIX, e);
            throw new IllegalStateException("Failed to configure DaoAuthenticationProvider", e);
        }
    }

    private void writeErrorResponse(HttpServletResponse response, String error, String message, int status) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status);
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", error);
        errorResponse.put("message", message);
        
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
    }
    
    /**
     * Handles JWT validation errors and formats appropriate error responses
     */
    /**
     * Custom filter to handle JWT exceptions
     */
    private static class ExceptionHandlingFilter extends OncePerRequestFilter {
        private final AuthenticationEntryPoint authenticationEntryPoint;

        public ExceptionHandlingFilter(AuthenticationEntryPoint authenticationEntryPoint) {
            this.authenticationEntryPoint = authenticationEntryPoint;
        }

        @Override
        protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request,
                                      jakarta.servlet.http.HttpServletResponse response,
                                      jakarta.servlet.FilterChain filterChain) throws jakarta.servlet.ServletException, java.io.IOException {
            try {
                filterChain.doFilter(request, response);
            } catch (AuthenticationException ex) {
                authenticationEntryPoint.commence(
                    (jakarta.servlet.http.HttpServletRequest) request,
                    (jakarta.servlet.http.HttpServletResponse) response,
                    ex
                );
            }
        }
    }

    /**
     * Custom BearerTokenResolver to handle token extraction
     */
    private static class CustomBearerTokenResolver implements BearerTokenResolver {
        private final BearerTokenResolver defaultResolver = new DefaultBearerTokenResolver();

        @Override
        public String resolve(jakarta.servlet.http.HttpServletRequest request) {
            try {
                return defaultResolver.resolve(request);
            } catch (Exception ex) {
                // Let the authentication entry point handle the exception
                throw new JwtException("Invalid token: " + ex.getMessage());
            }
        }
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("{}Configuring security filter chain", LOG_PREFIX);

        try {
            // Define public endpoints
            String[] publicEndpoints = {
                "/api/auth/login",
                "/public",
                "/public/**",
                "/error"
            };

            log.info("{}Configuring public endpoints: {}", LOG_PREFIX, Arrays.toString(publicEndpoints));

            // Configure JWT authentication converter
            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
            JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
            grantedAuthoritiesConverter.setAuthoritiesClaimName("scope");
            grantedAuthoritiesConverter.setAuthorityPrefix("SCOPE_");
            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
            jwtAuthenticationConverter.setPrincipalClaimName("sub");

            // Configure exception handlers
            AuthenticationEntryPoint authenticationEntryPoint = (request, response, authException) -> {
                log.warn("Authentication error: {}", authException.getMessage());
                
                // Create response JSON with the actual error message
                String error = "Unauthorized";
                String message = authException.getMessage() != null ? 
                    authException.getMessage() : "Authentication failed";
                
                // If there's a cause, include its message as well
                if (authException.getCause() != null && authException.getCause().getMessage() != null) {
                    message = authException.getCause().getMessage();
                }
                
                String jsonResponse = String.format(
                    "{\"error\":\"%s\",\"message\":\"%s\"}",
                    error,
                    message.replace("\"", "\\\\\"")
                );
                
                // Set response
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getWriter().write(jsonResponse);
            };

            AccessDeniedHandler accessDeniedHandler = (request, response, accessDeniedException) -> {
                log.warn("Access denied: {}", accessDeniedException.getMessage());
                // Match test expectations for forbidden access
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.getWriter().write("{\"error\":\"Forbidden\",\"message\":\"Access Denied\"}");
            };
            
            // Configure HTTP security
            http
                // Disable CSRF for stateless API
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())

                // Configure request authorization
                .authorizeHttpRequests(auth -> {
                    log.debug("{}Configuring authorization rules", LOG_PREFIX);
                    auth
                        // Public endpoints
                        .requestMatchers(publicEndpoints).permitAll()
                        // All other endpoints require authentication
                        .anyRequest().authenticated();
                })

                // Configure JWT
                .oauth2ResourceServer(oauth2 -> oauth2
                    .bearerTokenResolver(new CustomBearerTokenResolver())
                    .authenticationEntryPoint(authenticationEntryPoint)
                    .accessDeniedHandler(accessDeniedHandler)
                    .jwt(jwt -> jwt
                        .decoder(jwtDecoder())
                        .jwtAuthenticationConverter(jwtAuthenticationConverter)
                    )
                )

                // Configure session management
                .sessionManagement(session -> 
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Disable form login and basic auth
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)

                // Configure exception handling
                .exceptionHandling(exception -> exception
                    .authenticationEntryPoint(authenticationEntryPoint)
                    .accessDeniedHandler(accessDeniedHandler)
                );

            // Add custom filter to handle JWT exceptions
            http.addFilterBefore(new ExceptionHandlingFilter(authenticationEntryPoint), BearerTokenAuthenticationFilter.class);

            // Log the final security configuration
            log.info("{}Security filter chain configuration complete", LOG_PREFIX);
            return http.build();

        } catch (Exception e) {
            log.error("{}Failed to configure security filter chain", LOG_PREFIX, e);
            throw e;
        }
    }

    @Bean
    JwtDecoder jwtDecoder() {
        log.info("{}Configuring JwtDecoder with public key", LOG_PREFIX);
        try {
            RSAPublicKey publicKey = rsaKeyProperties.publicKey();
            log.debug("{}Using public key with algorithm: {}, format: {}",
                    LOG_PREFIX, publicKey.getAlgorithm(), publicKey.getFormat());

            JwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
            log.info("{}Successfully configured JwtDecoder", LOG_PREFIX);
            return decoder;

        } catch (Exception e) {
            log.error("{}Failed to configure JwtDecoder", LOG_PREFIX, e);
            throw e;
        }
    }

    @Bean
    JwtEncoder jwtEncoder() {
        log.info("{}Configuring JwtEncoder with RSA keys", LOG_PREFIX);
        try {
            RSAPublicKey publicKey = rsaKeyProperties.publicKey();
            RSAPrivateKey privateKey = rsaKeyProperties.privateKey();

            log.debug("{}Using public key (algorithm: {}, format: {}) and private key for JWT encoding",
                    LOG_PREFIX, publicKey.getAlgorithm(), publicKey.getFormat());

            JWK jwk = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .build();

            JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
            JwtEncoder encoder = new NimbusJwtEncoder(jwkSource);

            log.info("{}Successfully configured JwtEncoder", LOG_PREFIX);
            return encoder;

        } catch (Exception e) {
            log.error("{}Failed to configure JwtEncoder", LOG_PREFIX, e);
            throw e;
        }
    }
}