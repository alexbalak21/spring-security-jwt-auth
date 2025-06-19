package app;

import app.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Main application class for the JWT Authentication Service.
 * <p>
 * This application provides JWT-based authentication and authorization
 * using Spring Security and OAuth2 Resource Server.
 */
@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
public class AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

    /**
     * Security configuration for actuator endpoints.
     * Allows unauthenticated access to the public key endpoint.
     */
    @Bean
    public SecurityFilterChain actuatorSecurity(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/actuator/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(EndpointRequest.to("public-key")).permitAll()
                .anyRequest().authenticated()
            )
            .httpBasic();
        return http.build();
    }
}
