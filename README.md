# Spring Security JWT Authentication

This project demonstrates how to implement authentication and authorization using **Spring Security**, **JWT (JSON Web Tokens)**, and the **OAuth2 Resource Server** in a Spring Boot application with database-backed user authentication.

## 🚀 Features

- JWT-based authentication with OAuth2 Resource Server
- Secure REST API endpoints with role-based access control
- Stateless session management
- Database-backed user authentication (H2 in-memory database)
- Password hashing with BCrypt
- Custom UserDetailsService implementation
- RSA key pair for JWT signing and validation

## 🛠️ Technologies Used

- Java 17+
- Spring Boot 3.x
- Spring Security 6.x
- OAuth2 Resource Server
- Nimbus JOSE + JWT for JWT handling
- Spring Web for REST endpoints
- Maven for dependency management

## 📦 Prerequisites

- Java 17 or higher
- Maven 3.6.3 or higher

## 🚀 Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/spring-security-jwt-auth.git
   cd spring-security-jwt-auth
   ```

2. **Build the project**
   ```bash
   mvn clean install
   ```

3. **Run the application**
   ```bash
   mvn spring-boot:run
   ```

The application will start on `http://localhost:8080`

## 🔑 User Registration & Authentication

1. **Register a new user**:
   ```http
   POST /api/auth/register
   Content-Type: application/json
   
   {
       "username": "newuser",
       "email": "user@example.com",
       "password": "securePassword123"
   }
   ```

2. **Login to get JWT token**:
   ```http
   POST /api/auth/login
   Content-Type: application/json
   
   {
       "username": "newuser",
       "password": "securePassword123"
   }
   ```

## 🔐 Authentication

### Obtaining a JWT Token

To authenticate and obtain a JWT token, make a POST request to the `/api/auth/login` endpoint with a JSON body containing username and password:

```http
POST /api/auth/login
Content-Type: application/json

{
    "username": "your_username",
    "password": "your_password"
}
```

On successful authentication, you'll receive a JSON response containing the JWT token:

```json
{
    "AuthToken": "your.jwt.token.here"
}
```

### Using the JWT Token

Once you have the token, include it in the `Authorization` header for subsequent requests:

```http
GET /api/secure-endpoint
Authorization: Bearer your.jwt.token.here
```

## 🔧 Configuration

The application uses RSA key pair for JWT signing and validation. The keys are configured in `application.properties`:

```properties
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
```

For development, you can generate a new key pair using OpenSSL:

```bash
# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate public key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

## 🛡️ Security Configuration

The security configuration is defined in `SecurityConfig.java` and includes:

- Stateless session management
- JWT authentication with OAuth2 Resource Server
- Role-based access control
- CSRF protection disabled (for API usage)
- CORS configuration
- Custom UserDetailsService for database authentication
- Password encoding with BCrypt

## 📝 API Endpoints

| Method | Endpoint | Description | Authentication Required |
|--------|----------|-------------|-------------------------|
| POST   | /api/auth/register | Register new user | No |
| POST   | /api/auth/login    | Get JWT token | No (but requires valid credentials) |
| GET    | /api/secure/**     | Protected endpoints | JWT Bearer Token |

## 🧪 Testing

You can test the API using the provided `requests.http` file with HTTP Client support in IntelliJ IDEA or VS Code.

## 📚 Dependencies

- Spring Boot Starter Security
- Spring Boot Starter Web
- Spring Security OAuth2 Resource Server
- Spring Data JPA
- H2 Database (for development)
- Lombok (for reducing boilerplate code)
- Nimbus JOSE + JWT
- Spring Boot DevTools (for development)

## 🔒 Security Considerations

- Always use HTTPS in production
- Store private keys securely (e.g., in a key management service)
- Consider implementing token refresh mechanism
- Set appropriate token expiration times
- Use strong passwords in production
- Consider implementing rate limiting

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Prerequisites

- Java 17 or higher
- Maven 3.8+

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/spring-security-jwt-auth.git
   cd spring-security-jwt-auth
