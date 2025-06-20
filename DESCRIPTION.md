# Spring Security JWT Authentication - Comprehensive Class Documentation

This document provides an in-depth reference for all classes in the Spring Security JWT Authentication project, detailing their purpose, functionality, and implementation specifics.

## Core Application Class

### `AuthApplication.java`
- **Location**: `app`
- **Purpose**: Serves as the main entry point for the Spring Boot application.
- **Key Features**:
  - Bootstraps the Spring application context
  - Enables configuration properties binding for RSA keys
  - Sets up component scanning for the `app` package and its subpackages
- **Methods**:
  - `main(String[] args)`: Entry point that launches the Spring Boot application
- **Annotations**:
  - `@SpringBootApplication`: Composite annotation that combines:
    - `@Configuration`: Tags the class as a source of bean definitions
    - `@EnableAutoConfiguration`: Enables Spring Boot's auto-configuration
    - `@ComponentScan`: Enables component scanning for the current package
  - `@EnableConfigurationProperties(RsaKeyProperties.class)`: Enables `@ConfigurationProperties` support and binds them to the `RsaKeyProperties` class
- **Dependencies**:
  - `RsaKeyProperties` for RSA key configuration
  - Implicitly depends on Spring Boot's auto-configuration for web and security
- **Configuration Properties**:
  - Uses `application.yml` or `application.properties` for configuration
  - RSA keys are typically provided as environment variables or JVM properties

## Configuration Classes

### `SecurityConfig.java`
- **Location**: `app.config`
- **Purpose**: Central security configuration for the application, defining authentication and authorization rules.
- **Key Features**:
  - Configures HTTP security with JWT authentication
  - Sets up stateless session management
  - Defines in-memory user details service (for demonstration)
  - Configures JWT encoder and decoder using RSA keys
  - Disables CSRF protection for API usage
  - Enables CORS configuration
  - Configures OAuth2 Resource Server with JWT support

- **Methods**:
  - `user()`: Configures an in-memory user with default credentials
    - **Username**: alex
    - **Password**: password (with {noop} prefix indicating no password encoding)
    - **Roles**: USER
    - **Authorities**: read
  
  - `securityFilterChain(HttpSecurity http)`: Main security configuration
    - Disables CSRF protection
    - Requires authentication for all requests
    - Configures OAuth2 Resource Server with JWT
    - Sets session creation policy to STATELESS
    - Enables HTTP Basic authentication
    - Configures CORS
  
  - `jwtDecoder()`: Creates a JWT decoder using the public RSA key
  - `jwtEncoder()`: Creates a JWT encoder using the RSA key pair

- **Security Filters**:
  - `JwtAuthenticationFilter`: Validates JWT tokens in the Authorization header
  - `BasicAuthenticationFilter`: Handles Basic Authentication for the /token endpoint

- **Authentication Providers**:
  - `DaoAuthenticationProvider`: Authenticates users against the in-memory user details service

- **Annotations**:
  - `@Configuration`: Marks the class as a source of bean definitions
  - `@EnableMethodSecurity`: Enables method-level security with `@PreAuthorize`, `@PostAuthorize`, etc.
  - `@EnableWebSecurity`: Enables Spring Security's web security support

- **Dependencies**:
  - `RsaKeyProperties` for accessing RSA keys
  - `JwtEncoder` and `JwtDecoder` for JWT handling
  - `HttpSecurity` for configuring web security
  - `InMemoryUserDetailsManager` for user management

- **Security Headers**:
  - Configures default security headers
  - Disables frame options for H2 console (if used)
  - Sets up content security policy

- **CORS Configuration**:
  - Allows requests from any origin
  - Supports standard HTTP methods
  - Includes credentials in CORS requests
  - Sets max age to 3600 seconds (1 hour)

- **Session Management**:
  - Stateless session management (no session is created or used)
  - Session fixation protection is disabled (not needed for stateless applications)

### `RsaKeyProperties.java`
- **Location**: `app.config`
- **Purpose**: Configuration properties class that holds RSA key pairs for JWT signing and verification.
- **Key Features**:
  - Immutable record type for thread-safety
  - Binds RSA keys from external configuration
  - Provides type-safe access to cryptographic keys
  - Integrates with Spring's configuration property system

- **Record Components**:
  - `publicKey`: `RSAPublicKey` instance for JWT signature verification
  - `privateKey`: `RSAPrivateKey` instance for JWT signing

- **Configuration Properties**:
  - Properties are bound with prefix `rsa`
  - Keys are typically provided as PEM-encoded strings in environment variables:
    ```yaml
    rsa:
      private-key: ${JWT_PRIVATE_KEY}
      public-key: ${JWT_PUBLIC_KEY}
    ```

- **Key Format**:
  - Expects keys in PKCS#8 format (for private key) and X.509 format (for public key)
  - Keys should be in PEM format with proper headers/footers:
    ```
    -----BEGIN PRIVATE KEY-----
    [base64-encoded key]
    -----END PRIVATE KEY-----
    ```

- **Key Generation**:
  Keys can be generated using OpenSSL:
  ```bash
  # Generate private key (PKCS#8)
  openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
  
  # Generate public key
  openssl rsa -pubout -in private_key.pem -out public_key.pem
  ```

- **Security Considerations**:
  - Private key should be kept secure and never committed to version control
  - In production, use a secure key management system (e.g., AWS KMS, HashiCorp Vault)
  - Consider key rotation strategies for production use
  - Use environment variables or a secure secrets manager for key storage

- **Dependencies**:
  - `java.security.interfaces.RSAPrivateKey`
  - `java.security.interfaces.RSAPublicKey`
  - `org.springframework.boot.context.properties.ConfigurationProperties`

- **Usage in Application**:
  - Injected into `SecurityConfig` for JWT encoder/decoder configuration
  - Used by Spring Security for token signing and verification
  - Automatically bound by Spring Boot's configuration processor

- **Validation**:
  - Spring Boot validates that both keys are provided at startup
  - Keys must be valid RSA keys in the expected format
  - Key length should be at least 2048 bits for security

- **Testing Considerations**:
  - Test profile can use weaker keys or test-specific keys
  - Consider using a `@TestConfiguration` to provide test keys
  - Ensure test keys are different from production keys

## Controllers

### `AuthController.java`
- **Location**: `app.controller`
- **Purpose**: REST controller that handles authentication-related HTTP requests, specifically JWT token generation.
- **Key Features**:
  - Exposes a single endpoint for token generation
  - Integrates with Spring Security for authentication
  - Uses SLF4J for logging
  - Follows RESTful principles

- **Endpoints**:
  - `POST /token`
    - **Purpose**: Generates a new JWT token for authenticated users
    - **Authentication**: Basic Authentication (username/password)
    - **Request Body**: Empty JSON object `{}`
    - **Response**: JWT token string
    - **Status Codes**:
      - 200 OK: Token generated successfully
      - 401 Unauthorized: Invalid credentials
      - 500 Internal Server Error: Token generation failed

- **Method Details**:
  - `token(Authentication authentication)`
    - **Parameters**:
      - `authentication`: Spring Security's Authentication object (injected)
    - **Return Type**: `String` (the JWT token)
    - **Annotations**:
      - `@PostMapping("/token")`: Maps HTTP POST requests to this method
      - `@RestController`: Marks this class as a REST controller
    - **Flow**:
      1. Receives authenticated request (handled by Spring Security)
      2. Logs the token generation attempt
      3. Delegates to `TokenService` to generate JWT
      4. Returns the generated token

- **Dependencies**:
  - `TokenService`: For JWT token generation
  - `org.slf4j.Logger`: For application logging
  - `org.springframework.security.core.Authentication`: For accessing authenticated user details

- **Security Considerations**:
  - Endpoint is protected by Basic Authentication
  - No sensitive information is logged
  - Token expiration is handled by `TokenService`
  - Rate limiting should be considered for production use

- **Error Handling**:
  - Spring Security handles authentication failures
  - Uncaught exceptions return 500 status
  - Consider adding custom exception handlers for better error responses

- **Logging**:
  - Logs successful token generation with username
  - Uses debug/trace levels for detailed logging
  - No sensitive information is logged

- **Example Request**:
  ```http
  POST /token
  Authorization: Basic YWxleDpwYXNzd29yZA==
  Content-Type: application/json
  
  {}
  ```

- **Example Response**:
  ```json
  eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzZWxmIiwic3ViIjoiYWxleCIsImV4cCI6MTYyNzg5ODQwMCwiaWF0IjoxNjI3ODk0ODAwfQ...
  ```

- **Integration Points**:
  - Works with Spring Security's authentication system
  - Relies on `TokenService` for JWT creation
  - Can be extended with additional authentication methods (e.g., refresh tokens)

- **Testing**:
  - Unit tests should mock `TokenService`
  - Integration tests should verify the complete authentication flow
  - Test various authentication scenarios (valid/invalid credentials, expired tokens, etc.)

### `HomeController.java`
- **Location**: `app.controller`
- **Purpose**: Demonstrates a protected resource endpoint that requires JWT authentication.
- **Key Features**:
  - Simple example of a secured endpoint
  - Shows how to access authenticated user information
  - Demonstrates role-based access control

- **Endpoints**:
  - `GET /`
    - **Purpose**: Returns a personalized greeting
    - **Authentication**: JWT Bearer Token required
    - **Required Role**: USER (as defined in `SecurityConfig`)
    - **Response**: String greeting with username
    - **Status Codes**:
      - 200 OK: Successfully returns greeting
      - 401 Unauthorized: Missing or invalid JWT token
      - 403 Forbidden: Valid token but insufficient privileges

- **Method Details**:
  - `home(Principal principal)`
    - **Parameters**:
      - `principal`: Injected by Spring Security, represents the authenticated user
    - **Return Type**: `String` (the greeting message)
    - **Annotations**:
      - `@GetMapping("/")`: Maps HTTP GET requests to the root path
      - `@RestController`: Marks this class as a REST controller
    - **Flow**:
      1. Spring Security validates the JWT token
      2. If valid, injects the Principal
      3. Returns a personalized greeting

- **Dependencies**:
  - `java.security.Principal`: For accessing authenticated user information
  - Spring Web annotations for request mapping

- **Security Configuration**:
  - Protected by Spring Security
  - Requires valid JWT in Authorization header
  - Role-based access control (requires ROLE_USER)
  - Stateless session management

- **Example Request**:
  ```http
  GET /
  Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
  ```

- **Example Response**:
  ```
  Hello alex
  ```

- **Integration Points**:
  - Works with Spring Security's authentication system
  - Demonstrates JWT token validation
  - Shows how to access user information in controllers

- **Testing Considerations**:
  - Test with valid and invalid JWT tokens
  - Verify role-based access control
  - Test with expired tokens
  - Consider testing with different user roles

- **Potential Extensions**:
  - Add more detailed user information in the response
  - Implement additional endpoints with different access levels
  - Add request/response DTOs for type safety
  - Include HATEOAS links for API discoverability

- **Performance Considerations**:
  - Minimal processing overhead
  - JWT validation is handled efficiently by Spring Security
  - Consider caching user details if needed for complex authorization

## Services

### `TokenService.java`
- **Location**: `app.service`
- **Purpose**: Service responsible for JWT token generation and management.
- **Key Features**:
  - Creates signed JWT tokens with standard and custom claims
  - Configurable token expiration (default: 1 hour)
  - Includes user authorities in the token claims
  - Uses RSA for token signing
  - Thread-safe implementation

- **Class-Level Details**:
  - Annotated with `@Service` for Spring's component scanning
  - Constructor-injected dependencies
  - Uses SLF4J for logging

- **Method Details**:
  - `generateToken(Authentication authentication)`
    - **Purpose**: Generates a JWT token for an authenticated user
    - **Parameters**:
      - `authentication`: Spring Security Authentication object containing user details
    - **Return**: String containing the signed JWT
    - **Flow**:
      1. Extracts user authorities
      2. Builds JWT claims with standard and custom claims
      3. Sets token expiration
      4. Signs the token using the injected `JwtEncoder`
      5. Returns the compact token string

- **Token Claims**:
  - `iss` (Issuer): Set to "self"
  - `sub` (Subject): Username of the authenticated user
  - `iat` (Issued At): Current timestamp
  - `exp` (Expiration): Current timestamp + 1 hour
  - `scope`: Space-delimited list of user authorities

- **Dependencies**:
  - `JwtEncoder`: For signing and encoding JWTs
  - `org.springframework.security.core.Authentication`: For user authentication details
  - `java.time.Instant`: For timestamp handling
  - `java.time.temporal.ChronoUnit`: For time calculations

- **Configuration**:
  - Token expiration is hardcoded to 1 hour
  - Consider making this configurable via `application.properties`
  - Uses RSA 2048-bit keys by default

- **Security Considerations**:
  - Uses strong RSA signing
  - Tokens include minimal necessary claims
  - No sensitive information stored in tokens
  - Tokens are short-lived (1 hour)
  - Consider implementing token blacklisting for logout functionality

- **Error Handling**:
  - Propagates exceptions to the controller
  - Logs errors during token generation
  - Handles null or invalid authentication objects

- **Performance**:
  - Efficient string operations for claim building
  - Minimal object creation
  - Consider caching for high-load scenarios

- **Example Token**:
  ```json
  {
    "iss": "self",
    "sub": "alex",
    "exp": 1627898400,
    "iat": 1627894800,
    "scope": "ROLE_USER read"
  }
  ```

- **Testing**:
  - Unit tests should mock `JwtEncoder`
  - Test with different user roles and authorities
  - Verify token expiration and claims
  - Test error conditions

- **Extension Points**:
  - Add refresh token support
  - Implement token revocation
  - Add custom claims based on business requirements
  - Support for token audience and issuer validation

- **Dependencies**:
  - `org.springframework.security.oauth2.jwt.JwtEncoder`
  - `org.springframework.security.oauth2.jwt.JwtClaimsSet`
  - `org.springframework.security.core.Authentication`
  - `org.springframework.stereotype.Service`
  - `java.time.Instant`
  - `java.time.temporal.ChronoUnit`
  - `java.util.stream.Collectors`
  - `org.slf4j.Logger`

## Security Flow

1. **Authentication**:
   - Client sends credentials to `/token` endpoint
   - `AuthController` receives the request and delegates to `TokenService`
   - `TokenService` generates a JWT token

2. **Authorization**:
   - Client includes JWT in `Authorization: Bearer <token>` header
   - Spring Security validates the token using `JwtDecoder`
   - If valid, request is processed by the appropriate controller

3. **Security Configuration**:
   - `SecurityConfig` defines which endpoints are secured
   - RSA keys from `RsaKeyProperties` are used for JWT signing/verification

## Key Dependencies

- **Spring Boot Starter Security**: Core security framework
- **Spring Security OAuth2 Resource Server**: JWT support
- **Nimbus JOSE + JWT**: JWT implementation
- **Lombok**: Reduces boilerplate code

This structure provides a solid foundation for a secure REST API with JWT authentication that can be extended with additional features as needed.
