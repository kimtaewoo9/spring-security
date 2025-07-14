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
import software.springsecurity.entity.RefreshToken;
import software.springsecurity.entity.User;
import software.springsecurity.service.CustomUserDetailsService;
import software.springsecurity.service.RefreshTokenService;
import software.springsecurity.service.UserService;
import software.springsecurity.service.request.LoginRequest;
import software.springsecurity.service.request.RegisterRequest;
import software.springsecurity.service.request.TokenRefreshRequest;
import software.springsecurity.service.response.TokenRefreshResponse;
import software.springsecurity.utils.JwtUtils;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final UserService userService;
	private final JwtUtils jwtUtil;

	private final RefreshTokenService refreshTokenService;

	/**
	 * 사용자 로그인 (Refresh Token 포함)
	 *
	 * @param loginRequest 로그인 요청 정보
	 * @return Access Token과 Refresh Token
	 */
	@PostMapping("/login")
	public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
		try {
			// 로그인이 하는 일 .. ID 비밀번호 검증하고, access token 과 refresh token 을 발급한다 .

			// 인증 전용 토큰 객체를 authenticationManager 에게 전달함
			// 인증 전용 토큰 객체 -> 사용자의 아이디와 비밀번호만 담고, 인증 절차를 위해 AuthenticationManager 에게 전달되는
			// 	isAuthenticated() == false 상태으 Authentication 객체 .
			Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
					loginRequest.getUsername(),
					loginRequest.getPassword()
				)
			);

			// CustomUserPrincipal - > UserDetail 을 구현한 커스텀 클래스 .,
			User user = ((CustomUserDetailsService.CustomUserPrincipal) authentication.getPrincipal()).getUser();

			// Access Token 생성
			Map<String, Object> claims = Map.of(
				"role", user.getRole().name(),
				"email", user.getEmail(),
				"userId", user.getId()
			);
			String accessToken = jwtUtil.generateAccessToken(user.getUsername(), claims);

			// Refresh Token 생성
			RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

			// TODO refresh token 을 HttpOnly cookie 에 담아서 전송 ..
			Map<String, Object> response = Map.of(
				"accessToken", accessToken,
				"refreshToken", refreshToken.getToken(),
				"type", "Bearer",
				"expiresIn",
				jwtUtil.extractExpiration(accessToken).getTime() - System.currentTimeMillis(),
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
	 * 토큰 갱신 API Refresh Token을 사용하여 새로운 Access Token을 발급받는다.
	 *
	 * @param request Refresh Token 갱신 요청
	 * @return 새로운 Access Token과 Refresh Token
	 */
	@PostMapping("/refresh")
	public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
		try {
			// Refresh Token 검증 및 조회
			RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
				.orElseThrow(() -> new RuntimeException("유효하지 않거나 만료된 refresh token입니다."));

			// refresh token 에서 .. user 를 꺼내서 해당 정보로 access token 을 만든다 .
			User user = refreshToken.getUser();
			Map<String, Object> claims = Map.of(
				"role", user.getRole().name(),
				"email", user.getEmail(),
				"userId", user.getId()
			);
			String newAccessToken = jwtUtil.generateAccessToken(user.getUsername(), claims);

			refreshTokenService.markAsUsed(refreshToken);
			RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

			// 응답 생성
			TokenRefreshResponse response = new TokenRefreshResponse(
				newAccessToken,
				newRefreshToken.getToken(),
				jwtUtil.extractExpiration(newAccessToken).getTime() - System.currentTimeMillis()
			);

			return ResponseEntity.ok(response);

		} catch (RuntimeException e) {
			return ResponseEntity.badRequest()
				.body(Map.of("error", e.getMessage()));
		} catch (Exception e) {
			return ResponseEntity.internalServerError()
				.body(Map.of("error", "토큰 갱신 중 오류가 발생했습니다."));
		}
	}

	/**
	 * 로그아웃 (모든 토큰 무효화)
	 *
	 * @param request Refresh Token 정보
	 * @return 로그아웃 성공 메시지
	 */
	@PostMapping("/logout")
	public ResponseEntity<?> logout(@Valid @RequestBody TokenRefreshRequest request) {
		try {
			// 로그아웃하면 .. 그냥 refresh token 만 무효화하면 되나 ? access token 도 삭제해야하지 않나.
			RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
				.orElseThrow(() -> new RuntimeException("유효하지 않은 refresh token입니다."));

			// 사용자의 모든 토큰 무효화
			refreshTokenService.revokeAllUserTokens(refreshToken.getUser());

			return ResponseEntity.ok(Map.of(
				"message", "성공적으로 로그아웃되었습니다.",
				"timestamp", System.currentTimeMillis()
			));

		} catch (RuntimeException e) {
			return ResponseEntity.badRequest()
				.body(Map.of("error", e.getMessage()));
		} catch (Exception e) {
			return ResponseEntity.internalServerError()
				.body(Map.of("error", "로그아웃 처리 중 오류가 발생했습니다."));
		}
	}

	// 기존 register 메서드는 그대로 유지...
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
