package com.project.AuthenticationLayer.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/auth")
@Slf4j
public class AuthController {

    @PostMapping(value = "/register/signup")
    public String registerUser(){
        log.info("Registering new user ...");
        return "";
    }

    @PostMapping(value = "/login")
    public String loginUser(){
        log.info("Logging in user ...");
        return "";
    }

}
