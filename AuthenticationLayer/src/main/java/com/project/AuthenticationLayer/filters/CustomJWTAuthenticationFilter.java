package com.project.AuthenticationLayer.filters;

import com.project.AuthenticationLayer.filter_service.CustomJWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class CustomJWTAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private CustomJWTService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("Filtering request for authentication ....");
        //check if JWT is passed in request headers or not
        String authHeader = request.getHeader("Authorization");
        if(authHeader==null || authHeader.isEmpty() || authHeader.isBlank()){
            log.error("Authorization header not passed with request");
            response.sendError(403,"Auth header is null for authentication");
        }else{
            String jwtToken = authHeader.substring(7);
            if(jwtToken!=null || !jwtToken.isBlank() || !jwtToken.isEmpty()){
                log.info("JWT TOKEN FOUND");
                //parse the jwt token to get the subject / email
                String subject = jwtService.parseJWTtoken(jwtToken);
                filterChain.doFilter(request,response);
                return;
            }
            log.error("JWT TOKEN NOT PASSED FOR AUTHENTICATION");
            response.sendError(403,"JWT TOKEN NOT PASSED FOR AUTHENTICATION");
        }
    }
}
