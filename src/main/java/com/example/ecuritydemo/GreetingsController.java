package com.example.ecuritydemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {
    @GetMapping("/hello")
    public String sayHello(){
        return "Hello";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userEndpoint(){
        return "Hello User!!";
    }

    @GetMapping("/admin")
    public String adminEndpoint(){
        return "Hello Admin!!";
    }
}
