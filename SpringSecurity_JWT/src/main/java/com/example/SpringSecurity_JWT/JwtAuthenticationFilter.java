package com.example.SpringSecurity_JWT;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;


public class JwtAuthenticationFilter extends OncePerRequestFilter {



    private UserDetailsService userDetailsService;

    private JwtUtil jwtTokenUtil;

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(UserDetailsService userDetailsService, JwtUtil jwtTokenUtil, AuthenticationManager authenticationManager) {
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.authenticationManager = authenticationManager;
    }

    @Autowired


    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        String token = extractTokenFromRequest(req);
        String username =null;
        if (token != null) {
            try {
                username = jwtTokenUtil.getUsernameFromToken(token);
            } catch (IllegalArgumentException e) {
                logger.error("an error occured during getting username from token", e);
            } catch (ExpiredJwtException e) {
                logger.warn("the token is expired and not valid anymore", e);
            } catch(SignatureException e){
                logger.error("Authentication Failed. Username or Password not valid.");
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (validateToken(token)) { //Debugging purposes
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, Arrays.asList(new SimpleGrantedAuthority("ADMIN")));
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                    logger.info("authenticated user " + username + ", setting security context");
                    SecurityContextHolder.getContext().setAuthentication(authentication);
           }
        }
        chain.doFilter(req, res);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        return request.getHeader("Authorization");// Логика извлечения токена из запроса (например, из заголовка Authorization)
    }

    private boolean validateToken(String token) {
        return jwtTokenUtil.validateToken(token,extractUserDetailsFromToken(token));// Логика верификации токена
    }


    private Authentication createAuthentication(String token) {
        // Получение информации о пользователе из токена
        UserDetails userDetails = extractUserDetailsFromToken(token);

        // Создание объекта Authentication
        return new JwtAuthenticationToken(userDetails.getUsername(),userDetails.getPassword(),token);
    }

    private UserDetails extractUserDetailsFromToken(String token) {
        return userDetailsService.loadUserByUsername(jwtTokenUtil.getUsernameFromToken(token));
    }
}