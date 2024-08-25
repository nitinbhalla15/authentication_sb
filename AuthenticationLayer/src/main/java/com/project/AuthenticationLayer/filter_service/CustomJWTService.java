package com.project.AuthenticationLayer.filter_service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
public class CustomJWTService {

    @Value("${private.key}")
    private static String SECRET_KEY;

    public String generateTokenWithoutExtraClaims(UserDetails usr){
        return generateToken(null,usr);
    }

    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails usrDetails
    ){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(usrDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public String parseJWTtokenToUserEmail(String jwtToken){
        try{
            log.info("parsing jwt to user email ....");
            String jwtSubject = parseSingleClaim(jwtToken,Claims::getSubject);
            log.info("Subject parsed from JWT : ",jwtSubject);
            return jwtSubject;
        }catch (Exception e){
            log.error("Unable to send request to parse to parse jwt");
            return null;
        }
    }

    public <T> T parseSingleClaim(String jwtToken, Function<Claims,T> claimResolver){
        try{
            log.info("Parsing jwt to single claims");
            Claims allClaims = parseAllClaims(jwtToken);
            log.info("All claims : "+allClaims);
            return claimResolver.apply(allClaims);
        }catch (Exception e ){
            log.error("Unable to parse the jwt");
            return null;
        }
    }

    private Claims parseAllClaims(String jwtToken){
        log.info("Parsing JWT Token to claims...");
        try{
            return Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody();
        }catch (Exception e){
            log.error("Error while parsing jwt to claims");
            return null;
        }
    }


    private Key getSignInKey() {
        // Fetching sign in key / private key which will be used to decrypt jwt
        log.info("Fetching sign in key");
        byte[] keys = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keys);
    }

    public boolean isTokenValid(String token,UserDetails usrDetails){
        String userEmail = parseSingleClaim(token,Claims::getSubject);
        return (userEmail.equalsIgnoreCase(usrDetails.getUsername()) && !isTokenExpired(token));
    }

    public boolean isTokenExpired(String jwtToken){
        Date jwtExpTime = parseSingleClaim(jwtToken,Claims::getExpiration);
        return jwtExpTime.before(new Date());
    }


}
