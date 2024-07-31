package com.securitydemo.securitydemoapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan({"com.securitydemo.jwt", "com.securitydemo.securitydemoapp"})
public class SecuritydemoappApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuritydemoappApplication.class, args);
	}

}
