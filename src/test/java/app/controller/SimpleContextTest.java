package app.controller;

import app.config.AuthControllerTestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = {AuthControllerTestConfig.class})
@ActiveProfiles("test")
class SimpleContextTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void contextLoads() {
        assertNotNull(context, "Application context should load successfully");
        assertTrue(context.containsBean("testAuthenticationManager"), 
                 "Test AuthenticationManager should be in the context");
    }
}
