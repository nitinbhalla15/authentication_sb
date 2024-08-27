package com.project.AuthenticationLayer.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.awt.image.PackedColorModel;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "user_details")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegisterDetails implements UserDetails {

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

//    @Enumerated(EnumType.STRING)
//    private Role roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.getEmail_id();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
