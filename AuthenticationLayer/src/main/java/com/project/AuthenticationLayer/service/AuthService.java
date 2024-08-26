package com.project.AuthenticationLayer.service;


import com.project.AuthenticationLayer.entity.AuthenticationResponse;
import com.project.AuthenticationLayer.entity.LoginDetails;
import com.project.AuthenticationLayer.entity.RegisterUser;
import com.project.AuthenticationLayer.entity.UserRegisterDetails;
import com.project.AuthenticationLayer.filter_service.CustomJWTService;
import com.project.AuthenticationLayer.repo.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AuthService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository usrRepo;

    @Autowired
    private CustomJWTService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public AuthenticationResponse registerUser(RegisterUser user){
        log.info("Inside registerUser method");
        UserRegisterDetails usr = UserRegisterDetails.builder()
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email_id(user.getEmail())
                .password(passwordEncoder.encode(user.getPassword()))
                .build();
        usrRepo.save(usr);
        String token = jwtService.generateTokenWithoutExtraClaims(usr);
        AuthenticationResponse authResponse = AuthenticationResponse.builder()
                .token(token)
                .message("Successfully registered user").build();
        return authResponse;
    }

    public AuthenticationResponse authentication(LoginDetails loginCreds){
        log.info("Inside method authentication");
        authenticationManager.authenticate(
                 new UsernamePasswordAuthenticationToken(
                         loginCreds.getEmail_id(),
                         loginCreds.getPassword()
                 )
        );
        UserDetails usrDetails = usrRepo.findUserBySubject(loginCreds.getEmail_id())
                .orElseThrow();
        String token = jwtService.generateTokenWithoutExtraClaims(usrDetails);
        return AuthenticationResponse.builder().token(token)
                .message("Successfully fetched the token").build();
    }
}
