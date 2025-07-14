package software.springsecurity.service;

import jakarta.persistence.EntityNotFoundException;
import java.util.Collection;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import software.springsecurity.entity.User;
import software.springsecurity.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

	// 1. spring security 가 UserDetailService 의 loadByUsername() 메서드를 호출 .
	// 2. Custom User Detail Service 가 데이터베이스에서 사용자 정보 조회 .
	// 3. 조회한 정보를 UserDetail 객체로 변환하여 반환 ..

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username)
			.orElseThrow(() -> new EntityNotFoundException("유저 정보를 찾을 수 없습니다."));
		return new CustomUserPrincipal(user);
	}

	// Principal -> UserDetail 타입의 객체가 들어감 그걸 커스텀한거 .
	@RequiredArgsConstructor
	public static class CustomUserPrincipal implements UserDetails {

		// User 엔티티 객체를 spring security 에서 사용하는 UserDetail 객체로 변환해줌 .
		private final User user;

		// User 의 역할을 GrantedAuthority 로 변환함 .
		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			// 사용자의 역할을 Spring Security 권한으로 변환
			return Collections.singletonList(
				new SimpleGrantedAuthority(user.getRole().getAuthority()));
		}

		@Override
		public String getPassword() {
			return user.getPassword();
		}

		@Override
		public String getUsername() {
			return user.getUsername();
		}

		// 계정 만료 여부 (현재는 모든 계정이 만료되지 않음)
		@Override
		public boolean isAccountNonExpired() {
			return true;
		}

		// 계정 잠금 여부 (현재는 모든 계정이 잠기지 않음)
		@Override
		public boolean isAccountNonLocked() {
			return true;
		}

		// 자격 증명 만료 여부 (현재는 모든 자격 증명이 만료되지 않음)
		@Override
		public boolean isCredentialsNonExpired() {
			return true;
		}

		// 계정 활성화 여부
		@Override
		public boolean isEnabled() {
			return user.isEnabled();
		}

		// User 엔티티에 접근할 수 있는 메서드
		public User getUser() {
			return user;
		}
	}
}
