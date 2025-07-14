package software.springsecurity.service.request;

import lombok.Data;
import lombok.NoArgsConstructor;
import software.springsecurity.entity.Role;

@Data
@NoArgsConstructor

public class RegisterRequest {

	private String username;

	private String password;
	private String email;

	private Role role = Role.USER;
}
