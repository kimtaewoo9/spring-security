package software.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import software.springsecurity.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

}
