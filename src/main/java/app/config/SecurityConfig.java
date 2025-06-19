package app.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public InMemoryUserDetailsManager user(){
        return new InMemoryUserDetailsManager(
                User.
                        withUsername("alex")
                        .password("{noop}password")
                        .authorities("read")
                        .roles("USER")
                        .build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // 🔒 Disable CSRF protection since this is likely a stateless REST API
                .csrf(AbstractHttpConfigurer::disable)

                // ✅ Require authentication for *all* incoming HTTP requests
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )

                // 🔐 Configure the app as an OAuth2 Resource Server using JWT for token validation
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )

                // 📦 Make session handling stateless — no server-side sessions will be created
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 🔑 Enable HTTP Basic authentication — handy for testing with tools like curl or Postman
                .httpBasic(Customizer.withDefaults())

                // 🧱 Finalize the security configuration
                .build();
    }
}
