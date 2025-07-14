package software.springsecurity.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

	// 인증은 되었으나 .. 권한이 부족한 경우를 처리하는 컴포넌트
	private final ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void handle(HttpServletRequest request,
		HttpServletResponse response,
		AccessDeniedException accessDeniedException) throws IOException {

		// 응답 헤더 설정
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);

		// 현재 인증된 사용자 정보 가져오기
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String currentUser = authentication != null ? authentication.getName() : "익명";
		String currentRole = authentication != null && !authentication.getAuthorities().isEmpty()
			? authentication.getAuthorities().iterator().next().getAuthority()
			: "ROLE_NONE";

		// 에러 응답 메시지 구성
		Map<String, Object> body = new HashMap<>();
		body.put("status", HttpServletResponse.SC_FORBIDDEN);
		body.put("error", "FORBIDDEN");
		body.put("message", "접근 권한이 부족합니다.");
		body.put("path", request.getServletPath());
		body.put("timestamp", System.currentTimeMillis());
		body.put("currentUser", currentUser);
		body.put("currentRole", currentRole);
		body.put("hint", "해당 리소스에 접근하려면 더 높은 권한이 필요합니다. 관리자에게 문의하세요.");

		// JSON 응답 전송
		objectMapper.writeValue(response.getOutputStream(), body);
	}
}
