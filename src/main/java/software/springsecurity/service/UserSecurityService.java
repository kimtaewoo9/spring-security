package software.springsecurity.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import software.springsecurity.entity.User;
import software.springsecurity.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserSecurityService {

	private final UserRepository userRepository;

	public boolean isOwner(String username, Long resourceUserId) {
		try {
			User user = userRepository.findByUsername(username).orElse(null);
			return user != null && user.getId().equals(resourceUserId);
		} catch (Exception e) {
			return false;
		}
	}
	
	/**
	 * 사용자가 관리자이거나 리소스 소유자인지 확인한다.
	 *
	 * @param username       현재 인증된 사용자명
	 * @param resourceUserId 리소스 소유자 ID
	 * @return 관리자이거나 소유자이면 true
	 */
	public boolean isAdminOrOwner(String username, Long resourceUserId) {
		try {
			User user = userRepository.findByUsername(username).orElse(null);
			if (user == null) {
				return false;
			}

			// 관리자이거나 소유자인 경우
			return user.getRole().name().equals("ADMIN") || user.getId().equals(resourceUserId);
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * 사용자가 특정 역할 이상의 권한을 가지는지 확인한다.
	 *
	 * @param username    사용자명
	 * @param minimumRole 최소 요구 역할
	 * @return 권한이 충분하면 true
	 */
	public boolean hasMinimumRole(String username, String minimumRole) {
		try {
			User user = userRepository.findByUsername(username).orElse(null);
			if (user == null) {
				return false;
			}

			String userRole = user.getRole().name();

			// 역할 계층: ADMIN > MANAGER > USER
			return switch (minimumRole) {
				case "USER" -> true; // 모든 인증된 사용자
				case "MANAGER" -> userRole.equals("ADMIN") || userRole.equals("MANAGER");
				case "ADMIN" -> userRole.equals("ADMIN");
				default -> false;
			};
		} catch (Exception e) {
			return false;
		}
	}
}
