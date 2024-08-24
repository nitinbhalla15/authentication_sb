package com.project.AuthenticationLayer.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/authenticated")
@Slf4j
public class MainController {

    @GetMapping(value = "/init")
    public String init(){
        log.info("Hitting the main controller ....");
        return "Hey test successfull";
    }


}
