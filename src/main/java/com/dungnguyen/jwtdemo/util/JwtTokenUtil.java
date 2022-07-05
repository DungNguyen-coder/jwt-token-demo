package com.dungnguyen.jwtdemo.util;



import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.stream.Collectors;

//@Component
@Slf4j
@Data
//@PropertySource("classpath:application.properties")
public class JwtTokenUtil {

//    @Value("${jwt.secret}")
    private static String SECRET_KEY = "secret";
    private static Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

    public static String generateAccessToken(User user, HttpServletRequest request){
        log.info("Generate Access Token for username : {}", user.getUsername());
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 1*60*1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities()
                        .stream().map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .sign(algorithm);
    }

    public static String generateRefreshToken(User user, HttpServletRequest request){
        log.info("Generate Refresh Token for username : {}", user.getUsername());
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30*60*1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
    }

    public static DecodedJWT verifyToken(String token){
        log.info("Verify Token");
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }


}
