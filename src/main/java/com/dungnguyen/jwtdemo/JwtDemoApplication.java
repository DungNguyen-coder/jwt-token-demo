package com.dungnguyen.jwtdemo;

import com.dungnguyen.jwtdemo.model.Role;
import com.dungnguyen.jwtdemo.model.User;
import com.dungnguyen.jwtdemo.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.HashSet;

@SpringBootApplication
public class JwtDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtDemoApplication.class, args);
	}

//	@Bean
//	CommandLineRunner run(UserService userService){
//		return args -> {
//			userService.saveRole(new Role(null, "ROLE_USER"));
//			userService.saveRole(new Role(null, "ROLE_MANAGER"));
//			userService.saveRole(new Role(null, "ROLE_ADMIN"));
//			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
//
//			userService.saveUser(new User(null, "Dung Nguyen", "dungnguyen", "1234", new HashSet<>()));
//			userService.saveUser(new User(null, "Hoang Nam", "hoangnam", "1234", new HashSet<>()));
//			userService.saveUser(new User(null, "Ngan Ha", "hangan", "1234", new HashSet<>()));
//
//			userService.addRoleToUser("dungnguyen", "ROLE_SUPER_ADMIN");
//			userService.addRoleToUser("hoangnam", "ROLE_USER");
//			userService.addRoleToUser("hangan", "ROLE_MANAGER");
//			userService.addRoleToUser("hangan", "ROLE_ADMIN");
//
//
//		};
//	}
}
