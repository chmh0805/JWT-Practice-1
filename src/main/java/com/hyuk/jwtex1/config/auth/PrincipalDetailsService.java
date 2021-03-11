package com.hyuk.jwtex1.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.hyuk.jwtex1.domain.User;
import com.hyuk.jwtex1.domain.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("loadUserByUsername 실행됨");
		User userEntity = userRepository.findByUsername(username);
		
		if (userEntity == null) {
			return null;			
		} else {
			return new PrincipalDetails(userEntity);
		}
	}
}
