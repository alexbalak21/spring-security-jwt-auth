package app.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
public class HomeController {

    @GetMapping("/")
    public ResponseEntity<Map<String, String>> home(Principal principal) {
        String username = principal.getName();
        String capitalized = username.substring(0, 1).toUpperCase() + username.substring(1).toLowerCase();
        Map<String, String> response = new HashMap<>();
        response.put("message", "Hello " + capitalized);
        return ResponseEntity.ok(response);
    }
}