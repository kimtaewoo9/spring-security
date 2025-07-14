package software.springsecurity.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
public class RefreshToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String token; // refresh token 문자열을 저장하는 column

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id", nullable = false)
	private User user;

	private LocalDateTime expiresAt;

	private LocalDateTime createdAt;

	private LocalDateTime usedAt; // 새로운 access token 을 발급 받을 때 마다 .. 갱신함 .

	private boolean revoked = false;

	public RefreshToken(String token, User user, LocalDateTime expiresAt) {
		this.token = token;
		this.user = user;
		this.expiresAt = expiresAt;
		this.createdAt = LocalDateTime.now();
	}

	public boolean isExpired() {
		return LocalDateTime.now().isAfter(expiresAt);
	}

	public boolean isValid() {
		return !revoked && !isExpired();
	}
}
