package com.hyuk.jwtex1.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hyuk.jwtex1.config.auth.PrincipalDetails;
import com.hyuk.jwtex1.domain.dto.LoginReqDto;

import lombok.RequiredArgsConstructor;

// 토큰 만들어주기
@RequiredArgsConstructor
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;
	
	// POST 방식으로 주소 : /login 요청이 들어오면 동작
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("로그인 요청 옴.");
		
		ObjectMapper om = new ObjectMapper();
		LoginReqDto loginReqDto = null;
		
		try {
			loginReqDto = om.readValue(request.getInputStream(), LoginReqDto.class);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// 1. UsernamePassword 토큰 만들기
		UsernamePasswordAuthenticationToken authToken
			= new UsernamePasswordAuthenticationToken(loginReqDto.getUsername(), loginReqDto.getPassword());
		
		// 2. AuthenticationManager에게 토큰을 전달하면 -> 자동으로 UsersDetailService 호출 => 응답 Authentication
		Authentication authentication = authenticationManager.authenticate(authToken);
		return authentication;
	}
	
	// login 이 성공해서 Authentication 객체가 생성되면 동작
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("로그인 완료되어서 세션 만들어짐. 이제 JWT토큰 만들어서 response.header에 응답할 차례");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		// JWT 토큰은 보안 파일이 아니라 전자 서명을 위한 토큰이다.
		String jwtToken = JWT.create()
				.withSubject("blogToken") // 토큰 이름
				.withExpiresAt(new Date(System.currentTimeMillis() + 1000*60*10)) // 토큰 만료시각 : 현재시간 + 10분
				.withClaim("userId", principalDetails.getUser().getId()) // 개인정보가 아닌 값을 넣는게 좋다.
				.sign(Algorithm.HMAC512("홍길동")); // 임의의 키 부여(서버만 알아야 하는 값)
		
		System.out.println("jwtToken : " + jwtToken);
		response.setHeader("Authorization", "Bearer " + jwtToken);
	}
}
