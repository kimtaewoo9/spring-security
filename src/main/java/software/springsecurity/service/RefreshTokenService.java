package software.springsecurity.service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import software.springsecurity.config.JwtProperties;
import software.springsecurity.entity.RefreshToken;
import software.springsecurity.entity.User;
import software.springsecurity.repository.RefreshTokenRepository;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;
	private final JwtProperties jwtProperties;
	private final SecureRandom secureRandom = new SecureRandom();

	private static final int MAX_ACTIVE_TOKENS_PER_USER = 5;

	public RefreshToken createRefreshToken(User user) {
		long activeTokenCount = refreshTokenRepository.countActiveTokenByUser(user);

		if (activeTokenCount > MAX_ACTIVE_TOKENS_PER_USER) {
			// clean up old tokens ..
			refreshTokenRepository.revokeAllUserTokens(user);
		}

		String token = generateSecureRandomToken();
		LocalDateTime expiresAt = LocalDateTime.now()
			.plusSeconds(jwtProperties.refreshTokenExpiration() / 1000);

		RefreshToken refreshToken = new RefreshToken(token, user, expiresAt);
		return refreshTokenRepository.save(refreshToken);
	}

	public Optional<RefreshToken> findByToken(String token) {
		return refreshTokenRepository.findByToken(token)
			.filter(RefreshToken::isValid); // 1. refresh token 이 있는지 2. 해당 refresh token 이 유효한지.
	}

	// refresh token 을 사용 처리함 .
	public void markAsUsed(RefreshToken refreshToken) {
		refreshToken.setUsedAt(LocalDateTime.now());
		refreshTokenRepository.save(refreshToken);
	}

	public void revokeAllUserTokens(User user) {
		refreshTokenRepository.revokeAllUserTokens(user);
	}

	/**
	 * 특정 Refresh Token을 무효화한다.
	 *
	 * @param refreshToken 무효화할 RefreshToken
	 */
	public void revokeToken(RefreshToken refreshToken) {
		refreshToken.setRevoked(true);
		refreshTokenRepository.save(refreshToken);
	}

	/**
	 * 만료된 토큰들을 데이터베이스에서 삭제한다. 정기적으로 실행하여 저장소 크기 관리
	 */
	public void cleanupExpiredTokens() {
		refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
	}

	/**
	 * 사용자의 오래된 토큰들을 정리한다.
	 *
	 * @param user 정리할 사용자
	 */
	private void cleanupOldTokens(User user) {
		refreshTokenRepository.revokeAllUserTokens(user);
	}

	/**
	 * 암호학적으로 안전한 랜덤 토큰을 생성한다.
	 *
	 * @return Base64 인코딩된 랜덤 토큰 문자열
	 */
	private String generateSecureRandomToken() {
		byte[] tokenBytes = new byte[32]; // 256 비트 token 생성
		secureRandom.nextBytes(tokenBytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
	}
}
