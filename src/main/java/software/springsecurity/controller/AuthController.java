package software.springsecurity.controller;

import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import software.springsecurity.entity.User;
import software.springsecurity.service.CustomUserDetailService.CustomUserPrincipal;
import software.springsecurity.service.UserService;
import software.springsecurity.service.request.LoginRequest;
import software.springsecurity.service.request.RegisterRequest;
import software.springsecurity.utils.JwtUtils;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final UserService userService;
	private final JwtUtils jwtUtils;

	public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
		try {
			Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
					loginRequest.getUsername(),
					loginRequest.getPassword()
				)
			);

			// authentication.getPrincipal() -> 현재 인증된 사용자의 주체 객체를 반환함
			User user = ((CustomUserPrincipal) authentication.getPrincipal()).getUser();

			// jwt token 생성 ..
			Map<String, Object> claims = Map.of(
				"role", user.getRole().name(),
				"email", user.getEmail(),
				"userId", user.getId()
			);

			String accessToken = jwtUtils.generateAccessToken(user.getUsername(), claims);

			Map<String, Object> response = Map.of(
				"accessToken", accessToken,
				"type", "Bearer",
				"user", Map.of(
					"username", user.getUsername(),
					"email", user.getEmail(),
					"role", user.getRole().name()
				)
			);

			return ResponseEntity.ok(response);
		} catch (BadCredentialsException e) {
			return ResponseEntity.badRequest()
				.body(Map.of("error", "잘못된 사용자명 또는 비밀번호입니다."));
		} catch (AuthenticationException e) {
			return ResponseEntity.badRequest()
				.body(Map.of("error", "인증에 실패했습니다."));
		} catch (Exception e) {
			return ResponseEntity.internalServerError()
				.body(Map.of("error", "로그인 처리 중 오류가 발생했습니다."));
		}
	}

	/**
	 * 사용자 회원가입 API
	 *
	 * @param registerRequest 회원가입 요청 정보
	 * @return 생성된 사용자 정보
	 */
	@PostMapping("/register")
	public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
		try {
			User user = userService.createUser(
				registerRequest.getUsername(),
				registerRequest.getPassword(),
				registerRequest.getEmail(),
				registerRequest.getRole()
			);

			return ResponseEntity.ok(Map.of(
				"message", "회원가입이 완료되었습니다.",
				"username", user.getUsername(),
				"email", user.getEmail(),
				"role", user.getRole().name()
			));

		} catch (RuntimeException e) {
			return ResponseEntity.badRequest()
				.body(Map.of("error", e.getMessage()));
		} catch (Exception e) {
			return ResponseEntity.internalServerError()
				.body(Map.of("error", "회원가입 처리 중 오류가 발생했습니다."));
		}
	}
}
