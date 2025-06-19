# Spring Security JWT Authentication - Class Descriptions

This document provides a quick reference for all the classes in the Spring Security JWT Authentication project, explaining their purpose and functionality.

## Core Application Class

### `AuthApplication.java`
- **Location**: `app`
- **Purpose**: Main entry point of the Spring Boot application.
- **Key Features**:
    - Enables configuration properties for RSA keys
    - Starts the Spring Boot application context
- **Annotations**:
    - `@SpringBootApplication`: Enables Spring Boot auto-configuration and component scanning
    - `@EnableConfigurationProperties`: Enables `@ConfigurationProperties` annotated beans

## Configuration Classes

### `SecurityConfig.java`
- **Location**: `app.config`
- **Purpose**: Central security configuration for the application.
- **Key Features**:
    - Configures HTTP security rules
    - Sets up JWT authentication
    - Defines user details service (in-memory for demo)
    - Configures JWT encoder and decoder
- **Annotations**:
    - `@Configuration`: Marks the class as a source of bean definitions
    - `@EnableMethodSecurity`: Enables method-level security

### `RsaKeyProperties.java`
- **Location**: `app.config`
- **Purpose**: Holds RSA key properties for JWT signing and verification.
- **Key Features**:
    - Binds RSA keys from application properties
    - Provides typed access to public and private keys
- **Annotations**:
    - `@ConfigurationProperties("rsa")`: Binds properties with prefix "rsa"

## Controllers

### `AuthController.java`
- **Location**: `app.controller`
- **Purpose**: Handles authentication-related endpoints.
- **Endpoints**:
    - `POST /token`: Generates a JWT token for authenticated users
- **Dependencies**:
    - `TokenService` for JWT generation

### `HomeController.java`
- **Location**: `app.controller`
- **Purpose**: Example of a protected resource.
- **Endpoints**:
    - `GET /`: Returns a personalized greeting for authenticated users
- **Security**:
    - Requires valid JWT token

## Services

### `TokenService.java`
- **Location**: `app.service`
- **Purpose**: Handles JWT token generation.
- **Key Features**:
    - Generates JWT tokens with standard claims
    - Sets token expiration (1 hour by default)
    - Includes user authorities in the token
- **Dependencies**:
    - `JwtEncoder` for token creation

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
