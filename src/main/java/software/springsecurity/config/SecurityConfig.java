package software.springsecurity.config;

import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // 메서드 단위 보안 기능 활성화 @PreAuthorize 같은거 ..
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
	private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			.csrf(AbstractHttpConfigurer::disable) // 프론트랑 백엔드가 분리 되어 있으면 .. disable 해도 큰 문제가 없음 .
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			.sessionManagement(session -> session.sessionCreationPolicy(
				SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests(auth -> auth
				// 인증 불필요 경로
				.requestMatchers("/api/auth/**").permitAll()
				.requestMatchers("/api/public/**").permitAll()
				.requestMatchers("/h2-console/**").permitAll()
				// 관리자 전용 경로
				.requestMatchers("/api/admin/**").hasRole("ADMIN") // admin 권한 있는 사람만 접근 가능.
				// 매니저 이상 권한 경로
				.requestMatchers("/api/manager/**").hasAnyRole("ADMIN", "MANAGER")
				// 일반 사용자 이상 권한 경로
				.requestMatchers("/api/user/**").hasAnyRole("ADMIN", "MANAGER", "USER")
				// 나머지 모든 요청은 인증 필요
				.anyRequest().authenticated())
			.exceptionHandling(ex -> ex
				.authenticationEntryPoint(jwtAuthenticationEntryPoint)
				.accessDeniedHandler(jwtAccessDeniedHandler))
			.headers(headers -> headers
				.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
			// 로그인 폼을 보여주기 전에 먼저 jwt 토큰을 검증함 . 만약 jwt 토큰이 있으면 이 필터는 그냥 넘어간다.
			// Security Context Holder 가 존재하면 .. 추가 인증 x 바로 다음 필터로 .
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return httpSecurity.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();

		configuration.setAllowedOriginPatterns(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		configuration.setAllowCredentials(true);
		configuration.setExposedHeaders(Arrays.asList("Authorization"));
		configuration.setMaxAge(3600L); // preflight 요청 캐시 시간 (초)
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	// 해싱을 통한 암호화 .
	// BCrypt 에서는 비밀번호를 해싱할때 .. salt 라는 임의의 추가 데이터를 함께 사용함 .
	// 그래서 같은 비밀번호라도 . 해싱 결과가 매번 다르게 나온다 .
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(
		AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}
}
