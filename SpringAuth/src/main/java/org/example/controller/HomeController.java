package org.example.controller;

import lombok.extern.slf4j.Slf4j;
import org.example.models.Role;
import org.example.models.User;
import org.example.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Slf4j
@Controller
public class HomeController {

    private final UserService userService;

    @Autowired
    public HomeController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/home")
    public String home(@AuthenticationPrincipal OAuth2User principal) {
        String username = principal.getAttribute("username");
        User user = userService.findByUsername(username).get();
        if (user!=null) {
            if (user.getRoles().contains(Role.ADMIN)) {
                log.info("User " + user.getUsername()+"signed in as " + Role.ADMIN);
                return "redirect:/admin";
            } else if (user.getRoles().contains(Role.USER)) {
                log.info("User " + user.getUsername()+"signed in as " + Role.USER);
                return "redirect:/user";
            }
        }
        return "redirect:/user";
    }
}
