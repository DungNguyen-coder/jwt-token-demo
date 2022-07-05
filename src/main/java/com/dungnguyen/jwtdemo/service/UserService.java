package com.dungnguyen.jwtdemo.service;

import com.dungnguyen.jwtdemo.model.Role;
import com.dungnguyen.jwtdemo.model.User;

import java.util.List;

public interface UserService {
    User saveUser(User u);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
    List<Role> getRoles();
}
