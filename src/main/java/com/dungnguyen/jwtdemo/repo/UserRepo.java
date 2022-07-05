package com.dungnguyen.jwtdemo.repo;

import com.dungnguyen.jwtdemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
