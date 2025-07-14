package software.springsecurity.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.springsecurity.config.JwtProperties;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtUtils {

	private final SecretKey secretKey;
	private final JwtProperties jwtProperties;

	public String generateAccessToken(String username, Map<String, Object> additionalClaims) {
		// header 를 따로 지정하지 않아도됨 .

		Instant now = Instant.now();
		Instant expiration = now.plusMillis(jwtProperties.accessTokenExpiration());

		// 표준 클레임들은 전용 메서드로 넣고, 커스텀 claim 은 .claim(key, value) 로 추가.
		JwtBuilder builder = Jwts.builder()
			.subject(username) //
			.issuer(jwtProperties.issuer()) // 필수 아님
			.issuedAt(Date.from(now))
			.expiration(Date.from(expiration));

		if (additionalClaims != null) {
			// "role": "ADMIN" 등 커스텀 데이터만 넣음 .
			additionalClaims.forEach(builder::claim);
		}

		// header, payload, siginature 을 . 으로 합치는 작ㅇ버을 compact 라고 함 .
		return builder.signWith(secretKey).compact();
	}

	public String generateAccessToken(String username) {
		return generateAccessToken(username, null);
	}

	// 일반 jwt 토큰 ..
	public String generateToken(String username, Map<String, Object> additionalClaims) {
		Instant now = Instant.now();
		Instant expiration = now.plusMillis(jwtProperties.accessTokenExpiration());

		JwtBuilder builder = Jwts.builder()
			.subject(username)
			.issuer(jwtProperties.issuer())
			.issuedAt(Date.from(now))
			.expiration(Date.from(expiration));

		if (additionalClaims != null) {
			additionalClaims.forEach(builder::claim);
			// builder.claims("role", "admin");
			// builder.claims("email", "test@example.com";
			// .
		}

		// compact 란 ? 1. 헤더와 페이로드를 각각 인코딩 하고 . 으로 연결
		// 2. 이 문자열을 서명하고 서명 값도 인코딩
		// 3. header, payload, signature 부분을 . 으로 연결함
		return builder.signWith(secretKey).compact();
	}

	public String generateToken(String username) {
		return generateToken(username, null);
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parser()
				.verifyWith(secretKey)
				.requireIssuer(jwtProperties.issuer()) // 이 토큰이 변조되지 않았고, 내가 신뢰하는 사람이 만들었다는 증명 가능 .
				.build()
				.parseSignedClaims(token); // 이때 비로소 .. jwt 토큰 문자열을 파서에 전달함 .
			return true;
		} catch (ExpiredJwtException e) {
			log.debug("JWT 토큰이 만료되었습니다: {}", e.getMessage());
			return false;
		} catch (UnsupportedJwtException e) {
			log.debug("지원하지 않는 JWT 토큰입니다: {}", e.getMessage());
			return false;
		} catch (MalformedJwtException e) {
			log.debug("JWT 토큰 형식이 올바르지 않습니다: {}", e.getMessage());
			return false;
		} catch (SignatureException e) {
			log.debug("JWT 토큰의 서명이 유효하지 않습니다: {}", e.getMessage());
			return false;
		} catch (IllegalArgumentException e) {
			log.debug("JWT 토큰이 비어있거나 올바르지 않습니다: {}", e.getMessage());
			return false;
		} catch (JwtException e) {
			log.debug("JWT 토큰 검증 실패: {}", e.getMessage());
			return false;
		}
	}

	public boolean isTokenExpired(String token) {
		try {
			Claims claims = Jwts.parser()
				.verifyWith(secretKey)
				.build()
				.parseSignedClaims(token) // 토큰 파싱하고 claim 을 추출하기 .
				.getPayload();
			return claims.getExpiration().before(new Date()); // 현재 시간보다 만료 시간이 이전이여야함 .
		} catch (JwtException e) {
			log.debug("토큰 만료 확인 중 오류 발생: {}", e.getMessage());
			return true;
		}
	}

	public Date extractExpiration(String token) {
		return extractAllClaims(token).getExpiration();
	}

	/**
	 * 토큰에서 모든 클레임을 추출한다.
	 *
	 * @param token JWT 토큰
	 * @return Claims 객체
	 * @throws JwtException 토큰이 유효하지 않은 경우
	 */
	public Claims extractAllClaims(String token) {
		return Jwts.parser()
			.verifyWith(secretKey)
			.build()
			.parseSignedClaims(token)
			.getPayload();
	}

	public Long extractUserId(String token) {
		return null;
	}

	public String extractEmail(String token) {
		return null;
	}
}
