# Spring Security JWT - Quick Start Guide

Get up and running with the Spring Security JWT authentication system in minutes.

## Prerequisites

- Java 17 or higher
- Maven 3.6.3 or higher
- Your favorite IDE (IntelliJ IDEA, VS Code, etc.)

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/spring-security-jwt-auth.git
cd spring-security-jwt-auth
```

### 2. Configure Application Properties
Create or edit `src/main/resources/application.properties`:

```properties
# Server Configuration
server.port=8080

# Database Configuration (H2 in-memory for development)
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=password
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

# JPA/Hibernate
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.jpa.hibernate.ddl-auto=update

# JWT Configuration
jwt.secret=your-256-bit-secret
jwt.expiration=86400000  # 24 hours in milliseconds

# RSA Keys (generate your own for production)
rsa.private-key=your-private-key-here
rsa.public-key=your-public-key-here
```

### 3. Generate RSA Key Pair (Optional)
For production, generate your own RSA key pair:
```bash
# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate public key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

### 4. Build and Run
```bash
mvn clean install
mvn spring-boot:run
```

## Quick Test

### 1. Register a New User
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser", "email":"test@example.com", "password":"Password123!"}'
```

### 2. Login to Get JWT Token
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser", "password":"Password123!"}'
```

### 3. Access Protected Endpoint
```bash
# Copy the token from the login response
TOKEN=your-jwt-token-here

# Access protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/secure/me
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Authenticate and get JWT token
- `POST /api/auth/refresh` - Refresh access token (if implemented)

### Protected Endpoints
- `GET /api/secure/me` - Get current user details
- `GET /api/secure/admin` - Admin-only endpoint

## Development

### Database Console
Access H2 Console at: http://localhost:8080/h2-console
- JDBC URL: jdbc:h2:mem:testdb
- Username: sa
- Password: password

### Running Tests
```bash
mvn test
```

## Production Deployment

1. **Database**: Switch to a production database (PostgreSQL, MySQL, etc.)
2. **Security**:
   - Generate strong RSA keys
   - Set proper CORS configuration
   - Enable HTTPS
3. **Monitoring**: Add monitoring and logging
4. **Environment Variables**: Move sensitive data to environment variables

## Troubleshooting

### Common Issues
1. **H2 Console Not Accessible**
   - Ensure `spring.h2.console.enabled=true`
   - Check if port 8080 is available

2. **Authentication Fails**
   - Verify username/password
   - Check user exists in the database
   - Verify password encoding matches

3. **JWT Token Issues**
   - Check token expiration
   - Verify JWT secret/key configuration
   - Ensure proper Authorization header format

## Next Steps

1. Implement refresh token mechanism
2. Add email verification
3. Set up role-based access control
4. Configure CORS for your frontend
5. Add API documentation with Swagger/OpenAPI

## Support

For issues and feature requests, please [open an issue](https://github.com/yourusername/spring-security-jwt-auth/issues).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
