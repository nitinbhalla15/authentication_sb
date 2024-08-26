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

//    @Value("${private.key}")
    private static String SECRET_KEY="4226faeedf056aab435189c6f1eb2d723384295f8a3317843e733c5c17bef4ba3e40659681caf46a21c255828b50e5bbdbeb3a6e5884a20a69a219906022e94b415c3c7163bfaf19d91ee07188f6c0f80f93717b59477c8ff827b05560a15c5ac011e7b584c6fd4c919e717e182c3237a525c848e0ad1f26cc07acf89a1914ee5db86f2ec482f69d7f90e37121c8350a4e54c52e1d031375d40d3c4c6e84c2e2f5c154c268ee18e69d2cfd9b2821cd8473ffd1a0e6ce1a4ac61630f0851c50d55b49c726e1deb231f739704925650ad5b46fda3d1216a8bca1a5f49746064f6b09bfd6bd82f66e767f46270ccd8847d601555e398028147c60023b7ba3c6d887d68e5b012a4e39998bce22c39f110c3e28fbdf535ab800a435e6a019803dd72bfc5c3b9da767e6feb90c50bc33324bbd6518fec18ed52aabc2a2a686bb4a0b38f0af2f8cd311390b85324fbba52aad1dd0f78b507ebc55f4fa666e5b97a94c8d0234bd37172c3e409a723f3ae7123c8dbc3abd2c343130beb15c2e1309b5c893ca67548f476919f1f6195389e69b26581239e61c5837f861d91e299405b7be8a509cd456e3e69f0d9e48845eb386d2b3f6339f3e7506d6cb32c4ef59679b3cf614adfe2fb3945bb008bf650a6156c458a63dd513950959a27d9f690e7a15a17bdf7fe5a8cd039ecf956387b779494c4923ad1017e213058a1f831f810c9505e9";

    public String generateTokenWithoutExtraClaims(UserDetails usr){
        return generateToken(null,usr);
    }

    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails usrDetails
    ){
        return Jwts.builder()
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
