package software.springsecurity.service;

import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import software.springsecurity.entity.Role;
import software.springsecurity.entity.User;
import software.springsecurity.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	/**
	 * 새로운 사용자를 등록한다.
	 *
	 * @param username 사용자명
	 * @param password 평문 비밀번호 (암호화되어 저장됨)
	 * @param email    이메일
	 * @param role     사용자 역할
	 * @return 생성된 사용자 엔티티
	 */
	public User createUser(String username, String password, String email, Role role) {
		// 중복 검사
		if (userRepository.existsByUsername(username)) {
			throw new RuntimeException("이미 존재하는 사용자명입니다: " + username);
		}

		if (userRepository.existsByEmail(email)) {
			throw new RuntimeException("이미 존재하는 이메일입니다: " + email);
		}

		// 사용자 엔티티 생성
		User user = new User();
		user.setUsername(username);
		user.setPassword(passwordEncoder.encode(password)); // 비밀번호 암호화
		user.setEmail(email);
		user.setRole(role != null ? role : Role.USER);
		user.setEnabled(true);
		user.setCreatedAt(LocalDateTime.now());
		user.setUpdatedAt(LocalDateTime.now());

		return userRepository.save(user);
	}

	/**
	 * 사용자명으로 사용자를 조회한다.
	 */
	public User findByUsername(String username) {
		return userRepository.findByUsername(username)
			.orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다: " + username));
	}
}
