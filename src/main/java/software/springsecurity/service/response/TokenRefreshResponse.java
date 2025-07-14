package software.springsecurity.service.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenRefreshResponse {

	private String accessToken;
	private String refreshToken;
	private String type = "Bearer";
	private Long expiresIn;

	public TokenRefreshResponse(String accessToken, String refreshToken, Long expiresIn) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.expiresIn = expiresIn;
	}
}
