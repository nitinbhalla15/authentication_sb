package com.project.AuthenticationLayer.config;

import com.project.AuthenticationLayer.repo.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Slf4j
public class AppConfig {

    @Autowired
    private UserRepository usrRepo;

    @Bean
    public UserDetailsService userDetailsService(){
        log.info("Creating bean for userDetailsService ...");
        return username -> usrRepo.findUserBySubject(username).
                orElse(null);
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        log.info("Creating bean for Authentication provider ...");
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        log.info("Creating bean for passwordEncoder ...");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        log.info("Creating bean for authentication manager ...");
        return config.getAuthenticationManager();
    }
}
