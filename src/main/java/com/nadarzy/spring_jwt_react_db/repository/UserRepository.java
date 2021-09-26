package com.nadarzy.spring_jwt_react_db.repository;

import com.nadarzy.spring_jwt_react_db.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);
}
