package com.project.AuthenticationLayer.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginDetails {

    @NotNull(message = "Email id should not be blank or null")
    @NotBlank(message = "Email id should not be blank or null")
    @Email(message = "Incorrect email id syntax")
    private String email_id;
    @NotNull(message = "Password should not be blank or null")
    @NotBlank(message = "Password should not be blank or null")
    private String password;

}
