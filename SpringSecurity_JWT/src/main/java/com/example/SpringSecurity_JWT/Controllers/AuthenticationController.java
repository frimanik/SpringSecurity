package com.example.SpringSecurity_JWT.Controllers;

import com.example.SpringSecurity_JWT.JwtAuthenticationProvider;
import com.example.SpringSecurity_JWT.JwtAuthenticationToken;
import com.example.SpringSecurity_JWT.JwtUtil;
import com.example.SpringSecurity_JWT.Repositories.UserRepository;
import com.example.SpringSecurity_JWT.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/token")
public class AuthenticationController {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Autowired
    private JwtAuthenticationProvider authenticationManager;

    @Autowired
    public AuthenticationController(UserRepository userRepository,JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/generate")
    public JwtAuthenticationToken generate(@RequestBody User loginUser) throws AuthenticationException {

        final User user = userRepository.findByUsername(loginUser.getUsername());
        final String token = jwtUtil.generateToken(user.getUsername());
        return new JwtAuthenticationToken(user.getUsername(), user.getPassword(),token);
    }
}