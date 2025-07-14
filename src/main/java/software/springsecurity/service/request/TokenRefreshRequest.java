package software.springsecurity.service.request;

import lombok.Data;

@Data
public class TokenRefreshRequest {

	private String refreshToken;
}
