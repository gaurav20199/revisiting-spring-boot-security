package com.revisit.springsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/home")
    public String showHomePageContent() {
        return "Welcome to Home page!!";
    }
}
