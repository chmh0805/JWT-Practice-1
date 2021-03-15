package com.hyuk.jwtex1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.hyuk.jwtex1.config.jwt.JwtLoginFilter;
import com.hyuk.jwtex1.config.jwt.JwtVerifyFilter;
import com.hyuk.jwtex1.domain.UserRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final UserRepository userRepository;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// Bearer Auth
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.addFilter(new JwtLoginFilter(authenticationManager())) // 동작 : /login일 때만
			.addFilter(new JwtVerifyFilter(authenticationManager(), userRepository)) // 동작 : /login이 아닌 권한이 필요한 모든 요청
			.csrf().disable()
			.formLogin().disable() // Json 로그인을 해야하기 때문에 disable!!
			.httpBasic().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authorizeRequests() // 인증이나 권한이 필요한 요청
			.antMatchers("/user/**").access("hasRole('ROLE_USER')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll();
	}
	
}
