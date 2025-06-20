package app.service;

import app.dto.RegisterRequest;
import app.exception.UserAlreadyExistsException;
import app.model.Role;
import app.model.User;
import app.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticationService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User register(RegisterRequest request) {
        // Check if username already exists
        if (userRepository.existsByUsername(request.username())) {
            throw new UserAlreadyExistsException("Username is already taken");
        }
        
        // Create new user
        User user = new User(
            request.username(),
            passwordEncoder.encode(request.password()),
            Role.ROLE_USER  // Default role
        );
        
        return userRepository.save(user);
    }
}
