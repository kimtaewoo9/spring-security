package software.springsecurity.config;

import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

	// secret key 를 만들어서 보통 bean 으로 가지고 있는구나 !.
	// 하나의 비밀키로 서명과 검증을 모두 처리함 .
	@Bean
	public SecretKey jwtSecretKey(JwtProperties jwtProperties) {
		return Keys.hmacShaKeyFor(jwtProperties.secret().getBytes(StandardCharsets.UTF_8));
	}
}
