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
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

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
            throw e;
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
                "/public/**"
            };
            
            log.info("{}Configuring public endpoints: {}", LOG_PREFIX, Arrays.toString(publicEndpoints));
            
            // Configure HTTP security
            http
                // Disable CSRF for stateless API
                .csrf(AbstractHttpConfigurer::disable)
                
                // Configure request authorization
                .authorizeHttpRequests(auth -> {
                    log.debug("{}Configuring authorization rules", LOG_PREFIX);
                    auth
                        // Public endpoints
                        .requestMatchers(publicEndpoints).permitAll()
                        // All other endpoints require authentication
                        .anyRequest().authenticated();
                    
                    log.debug("{}Authorization rules configured: {} public endpoints, all others require authentication", 
                            LOG_PREFIX, publicEndpoints.length);
                })
                
                // Configure JWT
                .oauth2ResourceServer(oauth2 -> {
                    log.debug("{}Configuring OAuth2 Resource Server with JWT", LOG_PREFIX);
                    oauth2.jwt(Customizer.withDefaults());
                    log.debug("{}OAuth2 Resource Server configuration complete", LOG_PREFIX);
                })
                
                // Configure session management
                .sessionManagement(session -> {
                    log.debug("{}Configuring stateless session management", LOG_PREFIX);
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                
                // Disable form login and basic auth
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                
                // Configure exception handling
                .exceptionHandling(exception -> {
                    log.debug("{}Configuring exception handling with UNAUTHORIZED entry point", LOG_PREFIX);
                    exception.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
                });
            
            // Log the final security configuration
            log.info("{}Security filter chain configuration complete", LOG_PREFIX);
            log.debug("{}Security configuration complete", LOG_PREFIX);
            
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
