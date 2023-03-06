package com.anselm.springauthorizationserver;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.anselm.springauthorizationserver.users.User;
import com.anselm.springauthorizationserver.users.UserRepository;

@SpringBootApplication
public class SpringAuthorizationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringAuthorizationServerApplication.class, args);
	}
	
	@Bean
	public ApplicationRunner dataLoader(
			UserRepository repo, PasswordEncoder encoder) {
		return args -> {
			repo.save(
					new User("habuma", encoder.encode("password"), "ROLE_ADMIN"));
			repo.save(
					new User("tacochef", encoder.encode("password"), "ROLE_ADMIN"));
		};
	}
}
