package software.springsecurity.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import software.springsecurity.entity.RefreshToken;
import software.springsecurity.entity.User;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

	// token 으로 찾기 ..
	Optional<RefreshToken> findByToken(String token);

	// user 로 token 찾기 ..
	List<RefreshToken> findByUser(User user);

	@Modifying
	@Query("delete from RefreshToken rt where rt.user = :user")
	void deleteByUser(User user);

	@Modifying
	@Query("delete from RefreshToken rt where rt.expiresAt < :now")
	void deleteExpiredTokens(LocalDateTime now);

	@Modifying
	@Query("update RefreshToken rt set rt.revoked = true where rt.user = :user")
	void revokeAllUserTokens(User user);

	@Query("select count(rt) from RefreshToken rt where rt.user = :user and rt.revoked = false")
	long countActiveTokenByUser(User user);
}
