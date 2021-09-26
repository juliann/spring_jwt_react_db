package com.nadarzy.spring_jwt_react_db.service;

import com.nadarzy.spring_jwt_react_db.domain.Role;
import com.nadarzy.spring_jwt_react_db.domain.RoleEnum;
import com.nadarzy.spring_jwt_react_db.domain.User;
import com.nadarzy.spring_jwt_react_db.repository.RoleRepository;
import com.nadarzy.spring_jwt_react_db.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;

/** Created by Julian Nadarzy on 26/09/2021 */
@Service
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

  private final UserRepository userRepository;

  private final PasswordEncoder passwordEncoder;

  private final RoleRepository roleRepository;

  public UserServiceImpl(
      UserRepository userRepository,
      PasswordEncoder passwordEncoder,
      RoleRepository roleRepository) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.roleRepository = roleRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user =
        userRepository
            .findByUsername(username)
            .orElseThrow(
                () -> new UsernameNotFoundException("Username " + username + " not found"));

    return UserDetailsImpl.build(user);
  }

  @Override
  public User saveUser(User user) {
    log.info("saving User {}", user);
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    return userRepository.save(user);
  }

  @Override
  public Role saveRole(Role role) {
    log.info("saving Role {}", role);
    return roleRepository.save(role);
  }

  @Override
  public void addRoleToUser(String username, RoleEnum roleName) {
    log.info("adding role {} to user {}", roleName, username);
    Optional<User> optionalUser = userRepository.findByUsername(username);
    if (optionalUser.isPresent()) {
      Optional<Role> optionalRole = roleRepository.findByName(roleName);
      optionalRole.ifPresent(role -> optionalUser.get().getRoles().add(role));
    }
  }

  @Override
  public User getUser(String username) {
    log.info("getting User {}", username);
    return userRepository
        .findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("Username " + username + " not found"));
  }

  @Override
  public List<User> getUsers() {
    log.info("get all Users");
    return userRepository.findAll();
  }
}
