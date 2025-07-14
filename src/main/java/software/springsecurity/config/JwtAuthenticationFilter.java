package software.springsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import software.springsecurity.exception.JwtAuthenticationException;
import software.springsecurity.exception.JwtTokenMalformedException;
import software.springsecurity.exception.JwtTokenMissingException;
import software.springsecurity.utils.JwtUtils;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	// OncePerRequestFilter -> 요청당 딱 한번만 실행되는 필터 .
	private final JwtUtils jwtUtils;
	private final SecretKey secretKey;
	private final JwtProperties jwtProperties;


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		// 유효성 검증 + SecurityContextHolder 에 인증 정보 설정 .
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken == null) {
			return;
		}
		if (!bearerToken.startsWith("Bearer ")) {
			throw new JwtTokenMalformedException("Bearer 형식이 아닙니다.");
		}

		String token = bearerToken.substring(7);
		if (token.trim().isEmpty()) {
			throw new JwtTokenMissingException("Bearer 토큰이 비어있습니다.");
		}

		//
		if (token != null) {
			try {
				// 유효성 검증 ..
				Claims claims = Jwts.parser()
					.verifyWith(secretKey)
					.requireIssuer(jwtProperties.issuer()) // 발급자 검증 ..
					.build()
					.parseSignedClaims(token)
					.getPayload(); // 검증 한 다음 claim 을 파싱함 .

				String username = claims.getSubject();

				// 현재 SecurityContextHolder 에 인증 정보가 없는 경우만 처리 ..
				// jwt token 인 경우 매 요청마다 인증 정보를 새로 만들기 때문에 인증 정보가 없는 상태임 ..
				if (username != null
					&& SecurityContextHolder.getContext().getAuthentication() == null) {
					String role = claims.get("role").toString();

					// username 과 password 를 통해 인증 객체를 만듦 .
					// username -> UserDetails, authorities ..

					// jwt 토큰에 있는 권한 정보를 추출해서 SimpleGrantedAuthority 를 만든다.
					List<SimpleGrantedAuthority> authorities = Collections.singletonList(
						new SimpleGrantedAuthority("ROLE_" + role));

					// username, password, authorities 로 authentication 을 만들고 detail 설정 ..
					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						username, null, authorities);

					authentication.setDetails(
						new WebAuthenticationDetailsSource().buildDetails(request)
					);
					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			} catch (Exception ex) {
				// 기타 예외는 일반적인 인증 예외로 처리
				logger.error("JWT 인증 처리 중 예상치 못한 오류 발생", ex);
				request.setAttribute("jwt.exception",
					new JwtAuthenticationException("JWT 처리 중 내부 오류가 발생했습니다.", 500,
						"JWT_INTERNAL_ERROR"));
			}

			filterChain.doFilter(request, response);
		}
	}
}
