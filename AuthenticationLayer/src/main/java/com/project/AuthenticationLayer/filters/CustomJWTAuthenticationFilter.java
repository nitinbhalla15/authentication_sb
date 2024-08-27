package com.project.AuthenticationLayer.filters;

import com.project.AuthenticationLayer.filter_service.CustomJWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class CustomJWTAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private CustomJWTService jwtService;

    @Autowired
    private UserDetailsService usrDetailService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("Filtering request for authentication ....");
        //check if JWT is passed in request headers or not
        String authHeader = request.getHeader("Authorization");
        if(authHeader==null || authHeader.isEmpty() || authHeader.isBlank()){
            log.error("Authorization header not passed with request");
            filterChain.doFilter(request,response);
            return;
        }
        String jwtToken = authHeader.substring(7);
        if(jwtToken!=null || !jwtToken.isBlank() || !jwtToken.isEmpty()){
            log.info("JWT TOKEN FOUND");
            //parse the jwt token to get the subject / email
            String userEmail = jwtService.parseJWTtokenToUserEmail(jwtToken);
            if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null){
                //check if the user details exists in db with userEmail parsed from jwt
                // if not it means jwt was tampered and can send error -> auth failed
                log.info("JWT Token parsed to user email ...");
                UserDetails usrDetails = this.usrDetailService.loadUserByUsername(userEmail);
                if(usrDetails!=null && jwtService.isTokenValid(jwtToken,usrDetails)){
                    log.info("User Details found , authenticating user .....");
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(usrDetails,null,usrDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    //pass to the other filters and then to dispatcher servlet
                }
            }
            log.error("Either UserNot found || Invalid JWT || User Already Authenticated");
        }
        filterChain.doFilter(request,response);
    }
}
