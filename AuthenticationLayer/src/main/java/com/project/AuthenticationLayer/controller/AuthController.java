package com.project.AuthenticationLayer.controller;

import com.project.AuthenticationLayer.entity.AuthenticationResponse;
import com.project.AuthenticationLayer.entity.LoginDetails;
import com.project.AuthenticationLayer.entity.RegisterUser;
import com.project.AuthenticationLayer.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/auth")
@Slf4j
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping(value = "/register/signup")
    public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody RegisterUser usrDetails){
        log.info("Registering new user ...");
        return ResponseEntity.ok(authService.registerUser(usrDetails));
    }

    @PostMapping(value = "/login")
    public ResponseEntity<AuthenticationResponse> loginUser(@RequestBody LoginDetails loginDetails){
        log.info("Logging in user ...");
        return ResponseEntity.ok(authService.authentication(loginDetails));
    }

}
