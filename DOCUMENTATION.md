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
├── AuthApplication.java          # Main application class
├── config/
│   ├── SecurityConfig.java       # Security configuration
│   ├── RsaKeyProperties.java     # RSA key properties
│   └── CorsConfiguration.java    # CORS configuration
├── controller/
│   ├── AuthController.java      # Authentication endpoints
│   └── HomeController.java       # Protected resource
└── service/
    └── TokenService.java         # JWT token handling
```

## Authentication Flow

1. **Client Authentication**:
   - Client sends JSON credentials to `/login` endpoint
   - Server validates credentials using `AuthenticationManager`
   - On successful authentication, a JWT token is generated and returned in the response body

2. **Accessing Protected Resources**:
   - Client includes JWT token in the `Authorization: Bearer <token>` header
   - Server validates the token's signature and claims
   - If valid, access is granted to the protected resource

## Security Configuration

### SecurityConfig.java
- Enables method-level security with `@EnableMethodSecurity`
- Configures HTTP security to require authentication for all endpoints except `/login`
- Sets up JWT-based authentication using OAuth2 Resource Server
- Configures stateless session management
- Disables CSRF protection (as we're using JWT)
- Configures `AuthenticationManager` for JSON authentication
- Sets up password encoding with BCrypt

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

#### Get JWT Token
- **Endpoint**: `POST /login`
- **Request Headers**:
  ```
  Content-Type: application/json
  ```
- **Request Body**:
  ```json
  {
    "username": "alex",
    "password": "password"
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
Configuration is managed through `application.yml`:

```yaml
server:
  port: 8080

rsa:
  private-key: ${JWT_PRIVATE_KEY}  # Private key for JWT signing
  public-key: ${JWT_PUBLIC_KEY}    # Public key for JWT verification

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080  # JWT issuer URI
```

### Environment Variables
- `JWT_PRIVATE_KEY`: RSA private key for JWT signing
- `JWT_PUBLIC_KEY`: RSA public key for JWT verification

## Security Considerations

### Key Management
- **Development**: Keys can be stored in environment variables
- **Production**: Use a secure key management system (e.g., AWS KMS, HashiCorp Vault)
- **Key Rotation**: Implement a key rotation strategy

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

### Generating RSA Key Pair

```bash
# Generate private key (PKCS#8 format)
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate public key
openssl rsa -pubout -in private_key.pem -out public_key.pem

# Convert to single line for environment variables
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' private_key.pem
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' public_key.pem
```

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
