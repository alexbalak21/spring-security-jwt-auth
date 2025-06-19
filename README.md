# Spring Security JWT Authentication

This project demonstrates how to implement authentication and authorization using **Spring Security**, **JWT (JSON Web Tokens)**, and the **OAuth2 Resource Server** in a Spring Boot application.

## 🚀 Features

- JWT-based authentication
- OAuth2 resource server support
- Secure REST API endpoints
- Stateless session management
- RSA key pair for JWT signing and validation
- In-memory user details service (for demonstration purposes)

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

## 🔑 Default User Credentials

For demonstration purposes, the application comes with a default user:

- **Username:** alex
- **Password:** password

## 🔐 Authentication

### Obtaining a JWT Token

To authenticate and obtain a JWT token, make a POST request to the `/token` endpoint with Basic Authentication:

```http
POST /token
Authorization: Basic YWxleDpwYXNzd29yZA==
Content-Type: application/json

{}
```

Where `YWxleDpwYXNzd29yZA==` is the Base64 encoded string of `username:password` (alex:password).

### Using the JWT Token

Once you have the token, include it in the `Authorization` header for subsequent requests:

```http
GET /
Authorization: Bearer your.jwt.token.here
```

## 🔧 Configuration

The application uses RSA key pair for JWT signing and validation. The keys are configured in `application.yml`:

```yaml
rsa:
  private-key: ${JWT_PRIVATE_KEY}
  public-key: ${JWT_PUBLIC_KEY}
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
- JWT authentication
- Role-based access control
- CSRF protection disabled (for API usage)
- CORS configuration

## 📝 API Endpoints

| Method | Endpoint | Description | Authentication Required |
|--------|----------|-------------|-------------------------|
| POST   | /token   | Get JWT token | Basic Auth |
| GET    | /        | Home endpoint | JWT Bearer Token |

## 🧪 Testing

You can test the API using the provided `requests.http` file with HTTP Client support in IntelliJ IDEA or VS Code.

## 📚 Dependencies

- Spring Boot Starter Security
- Spring Boot Starter Web
- Spring Security OAuth2 Resource Server
- Nimbus JOSE + JWT
- Lombok (for reducing boilerplate code)
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
