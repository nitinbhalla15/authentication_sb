package com.project.AuthenticationLayer.entity;

import lombok.Data;

@Data
public class RegisterUser {

    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
