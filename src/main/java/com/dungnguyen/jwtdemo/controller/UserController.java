package com.dungnguyen.jwtdemo.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.dungnguyen.jwtdemo.model.Role;
import com.dungnguyen.jwtdemo.model.User;
import com.dungnguyen.jwtdemo.service.UserService;
import com.dungnguyen.jwtdemo.service.UserServiceImpl;
import com.dungnguyen.jwtdemo.util.JwtTokenUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserServiceImpl service;


    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers(){
        return ResponseEntity.ok().body(service.getUsers());
    }

    @PostMapping("/user")
    public ResponseEntity<User> addNewUser(@RequestBody User user){
        URI uri = URI.create(ServletUriComponentsBuilder.
                fromCurrentContextPath().path("/user").toUriString());
        return ResponseEntity.created(uri).body(service.saveUser(user));
    }

    @GetMapping("/user")
    public ResponseEntity<User> getUser(@RequestParam("username") String username){
        return ResponseEntity.ok().body(service.getUser(username));
    }

    @PostMapping("/role")
    public ResponseEntity<Role> addNewRole(@RequestBody Role role){
        URI uri = URI.create(ServletUriComponentsBuilder.
                fromCurrentContextPath().path("/role").toUriString());
        return ResponseEntity.created(uri).body(service.saveRole(role));
    }

    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getRoles(){
        return ResponseEntity.ok().body(service.getRoles());
    }

    @PostMapping("/add-role")
    public void addRoleToUser(@RequestBody RoleToUserForm roleToUserForm){
        service.addRoleToUser(roleToUserForm.getUsername(), roleToUserForm.getRoleName());
    }

    @GetMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response){
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                DecodedJWT decodedJWT = JwtTokenUtil.verifyToken(refresh_token);
                String username = decodedJWT.getSubject();
                org.springframework.security.core.userdetails.User user =
                        (org.springframework.security.core.userdetails.User) service.loadUserByUsername(username);

                Collection<GrantedAuthority> authorities = user.getAuthorities();

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                response.setHeader("access_token", JwtTokenUtil.generateAccessToken(user, request));
                response.setHeader("refresh_token", JwtTokenUtil.generateRefreshToken(user, request));


            } catch (Exception e){
                log.error("Refreshing Token is not successful : {}", e.getMessage());

                // add message to header
                response.setHeader("error", e.getMessage());
//                    response.sendError(HttpServletResponse.SC_FORBIDDEN);

                // add message to body
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                Map<String, String> error = new HashMap<>();
                error.put("error_message", e.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                try {
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                } catch (Exception exception){
                    log.error("Response error : {}", e.getMessage());
                }

            }
        } else {
            // to continue next filter
            log.error("Refresh Token is not valid or missing");
            throw new RuntimeException("Refresh Token is not valid or missing");
        }
    }

}
@Data
final class RoleToUserForm {
    private String username;
    private String roleName;
}