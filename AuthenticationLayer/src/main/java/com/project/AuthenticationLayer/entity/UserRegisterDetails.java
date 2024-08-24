package com.project.AuthenticationLayer.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.awt.image.PackedColorModel;
import java.util.UUID;

@Entity
@Table(name = "user_details")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserRegisterDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID user_id;
    @NotNull(message = "First name should not be blank or null")
    @NotBlank(message = "First name should not be blank or null")
    private String firstName;
    private String lastName;
    @NotNull(message = "Email id should not be blank or null")
    @NotBlank(message = "Email id should not be blank or null")
    @Email(message = "Incorrect email id syntax")
    private String email_id;
    @JsonProperty(access=JsonProperty.Access.WRITE_ONLY)
    private String password;


}
