# Spring Security JWT Authentication - Technical Documentation

## Table of Contents
1. [Project Structure](#project-structure)
2. [Authentication Flow](#authentication-flow)
3. [Security Configuration](#security-configuration)
4. [JWT Implementation](#jwt-implementation)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

## Project Structure

```
src/main/java/app/
├── config/
│   ├── SecurityConfig.java       # Security configuration
│   ├── RsaKeyProperties.java     # RSA key properties
│   └── JwtConfig.java           # JWT configuration
├── controller/
│   ├── AuthController.java      # Authentication endpoints
│   └── HomeController.java       # Protected resource
├── service/
│   ├── UserDetailsServiceImpl.java # Custom UserDetailsService
│   └── JwtService.java          # JWT token handling
├── model/
│   ├── User.java                # User entity
│   └── Role.java                 # User roles
└── repository/
    └── UserRepository.java      # User repository
```

## Authentication Flow

1. **User Registration**:
   - Client sends registration request to `/api/auth/register`
   - Server validates input and creates new user with hashed password
   
2. **Client Authentication**:
   - Client sends JSON credentials to `/api/auth/login` endpoint
   - Server validates credentials against database using `UserDetailsService`
   - On successful authentication, a JWT token is generated and returned in the response body

2. **Accessing Protected Resources**:
   - Client includes JWT token in the `Authorization: Bearer <token>` header
   - Server validates the token's signature and claims
   - If valid, access is granted to the protected resource

## Security Configuration

### SecurityConfig.java
- Enables method-level security with `@EnableMethodSecurity`
- Configures HTTP security to require authentication for all endpoints except `/api/auth/**`
- Sets up JWT-based authentication using OAuth2 Resource Server
- Configures stateless session management
- Disables CSRF protection (as we're using JWT)
- Configures `AuthenticationManager` to use custom `UserDetailsService`
- Sets up password encoding with BCrypt
- Configures OAuth2 Resource Server for JWT validation

### CORS Configuration
- Allows cross-origin requests from any origin (configured in `CorsConfiguration.java`)
- Can be customized based on your requirements

## JWT Implementation

### Token Generation (`TokenService.java`)
- Uses RSA key pair for signing and verification
- Sets standard JWT claims (issuer, subject, issued at, expiration)
- Includes custom claims as needed
- Signs the token using the private key

### Token Validation
- Validates token signature using the public key
- Verifies standard claims (expiration, issuer, etc.)
- Extracts user authorities from the token

## API Reference

### Authentication

#### Register New User
- **Endpoint**: `POST /api/auth/register`
- **Request Headers**:
  ```
  Content-Type: application/json
  ```
- **Request Body**:
  ```json
  {
    "username": "newuser",
    "email": "user@example.com",
    "password": "securePassword123"
  }
  ```

#### Get JWT Token
- **Endpoint**: `POST /api/auth/login`
- **Request Headers**:
  ```
  Content-Type: application/json
  ```
- **Request Body**:
  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```
- **Response**:
  ```json
  {
    "AuthToken": "eyJhbGciOiJSUzI1NiJ9..."
  }
  ```

### Protected Resources

#### Get Home
- **Endpoint**: `GET /`
- **Authentication**: JWT Bearer Token
- **Request Headers**:
  ```
  Authorization: Bearer <jwt-token>
  ```
- **Response**:
  ```json
  {
    "message": "Hello, alex!"
  }
  ```

## Configuration

### Application Properties
Configuration is managed through `application.properties`:

```properties
# Server Configuration
server.port=8080

# JWT Configuration
jwt.secret=your-secret-key
jwt.expiration=86400000  # 24 hours in milliseconds

# Database (H2 in-memory for development)
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

# JPA/Hibernate
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=true

# OAuth2 Resource Server
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8080
```

### Environment Variables
- `JWT_SECRET`: Secret key for JWT signing and verification
- `JWT_EXPIRATION`: JWT expiration time in milliseconds (default: 86400000 - 24 hours)

## Security Considerations

### Security Best Practices
- **Development**: Use strong secrets and enable H2 console only in development
- **Production**: 
  - Use environment variables for sensitive data
  - Enable HTTPS
  - Use a production-grade database (PostgreSQL, MySQL, etc.)
  - Configure proper CORS settings
  - Implement rate limiting
  - Use proper logging and monitoring

### Token Security
- Use short-lived access tokens (15-60 minutes)
- Implement refresh token mechanism for long-lived sessions
- Store tokens securely in HTTP-only cookies or secure storage
- Use HTTPS in production to prevent token interception

### Rate Limiting
Consider implementing rate limiting to prevent brute force attacks:
- Limit login attempts
- Throttle token generation

## Troubleshooting

### Common Issues

1. **Invalid Credentials**
   - Verify username and password
   - Check that the Basic Auth header is correctly encoded

2. **Invalid or Expired Token**
   - Check token expiration time
   - Verify token signature with the public key
   - Ensure the token hasn't been tampered with

3. **Access Denied**
   - Verify the user has the required roles/authorities
   - Check token claims for required scopes

4. **CORS Issues**
   - Verify CORS configuration
   - Ensure proper headers are sent with preflight requests

### Logging
Enable debug logging for security-related packages:

```yaml
logging:
  level:
    org.springframework.security: DEBUG
    app: DEBUG
```

## Development

### Testing the API

You can use the provided `requests.http` file to test the API endpoints:

1. Register a new user
2. Login with the registered credentials
3. Access protected endpoints with the JWT token

### Database Access

During development, you can access the H2 console at:
- URL: http://localhost:8080/h2-console
- JDBC URL: jdbc:h2:mem:testdb
- Username: sa
- Password: (leave empty)

### Testing

Run the application and test using the provided `requests.http` file or tools like cURL:

```bash
# Get token
curl -X POST http://localhost:8080/token \
  -H "Authorization: Basic YWxleDpwYXNzd29yZA==" \
  -H "Content-Type: application/json"

# Access protected resource
curl -X GET http://localhost:8080/ \
  -H "Authorization: Bearer <jwt-token>"
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
