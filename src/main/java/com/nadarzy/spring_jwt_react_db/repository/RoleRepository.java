package com.nadarzy.spring_jwt_react_db.repository;

import com.nadarzy.spring_jwt_react_db.domain.Role;
import com.nadarzy.spring_jwt_react_db.domain.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(RoleEnum name);
}
