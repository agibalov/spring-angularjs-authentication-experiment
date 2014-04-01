package me.loki2302;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

public class App {
    public static void main(String[] args) {
        SpringApplication.run(AppConfiguration.class, args);
    }

    @Configuration
    @ComponentScan
    @EnableAutoConfiguration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class AppConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(HttpSecurity httpSecurity) throws Exception {
            httpSecurity.csrf().disable();
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring().antMatchers(
                    "/",
                    "/index.html",
                    "/css/**",
                    "/fonts/**",
                    "/js/**");
        }
    }

    @RestController
    @RequestMapping("/api")
    public static class HomeController {
        @Autowired
        private AuthenticationManager authenticationManager;

        @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
        public Me authenticate(@RequestBody AuthenticationRequest authenticationRequest) {
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.username,
                    authenticationRequest.password);

            Authentication authentication;
            try {
                authentication = authenticationManager.authenticate(token);
            } catch(AuthenticationException e) {
                throw new InvalidCredentialsException();
            }

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Me me = new Me();
            me.username = authentication.getName();
            return me;
        }

        @PreAuthorize("isAuthenticated()")
        @RequestMapping(value = "/me", method = RequestMethod.GET)
        public Me getMe(Authentication authentication) {
            Me me = new Me();
            me.username = authentication.getName();
            return me;
        }

        @PreAuthorize("isAuthenticated()")
        @RequestMapping(value = "/deauthenticate", method = RequestMethod.POST)
        public Me deauthenticate() {
            SecurityContextHolder.clearContext();
            return null;
        }
    }

    @ControllerAdvice
    public static class ErrorHandler {
        @ExceptionHandler(InvalidCredentialsException.class)
        @ResponseStatus(HttpStatus.UNAUTHORIZED)
        @ResponseBody
        public ErrorDto unauthorized(InvalidCredentialsException e) {
            ErrorDto errorDto = new ErrorDto();
            errorDto.message = "Unauthorized";
            return errorDto;
        }

        @ExceptionHandler(AccessDeniedException.class)
        @ResponseStatus(HttpStatus.FORBIDDEN)
        @ResponseBody
        public ErrorDto forbidden(AccessDeniedException e) {
            ErrorDto errorDto = new ErrorDto();
            errorDto.message = "Forbidden";
            return errorDto;
        }

        @ExceptionHandler(RuntimeException.class)
        @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
        @ResponseBody
        public ErrorDto internalServerError(RuntimeException e) {
            ErrorDto errorDto = new ErrorDto();
            errorDto.message = "Runtime error";
            return errorDto;
        }
    }

    public static class Me {
        public String username;
    }

    public static class AuthenticationRequest {
        public String username;
        public String password;
    }

    public static class ErrorDto {
        public String message;
    }

    public static abstract class ApiException extends RuntimeException {
    }

    public static class InvalidCredentialsException extends ApiException {
    }
}
