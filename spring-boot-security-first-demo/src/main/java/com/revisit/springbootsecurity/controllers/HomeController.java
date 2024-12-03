package com.revisit.springbootsecurity.controllers;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/home")
    public String homePage() {
        var u = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(u.getPrincipal()+","+u.getAuthorities());
        return "Logged in to home page";
    }
}
