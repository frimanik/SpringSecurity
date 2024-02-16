package com.example.SpringSecurity_JWT.Controllers;

import com.example.SpringSecurity_JWT.Repositories.UserRepository;
import com.example.SpringSecurity_JWT.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    private final UserRepository userRepository;

    @Autowired
    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostMapping ("/users")
    public User saveUser(@RequestBody User user) {
        return userRepository.save(user);
    }


    @GetMapping("/check")
    public String checkAuth() {
        return "You're in";
    }

    @Secured("MODERATOR")
    @GetMapping("/checkModerator")
    public String checkModeratorRole(){
        return  "You're in as Moderator";
    }

    @Secured("ADMIN")
    @GetMapping("/checkAdmin")
    public String checkAdminRole(){
        return  "You're in as Admin";
    }
}