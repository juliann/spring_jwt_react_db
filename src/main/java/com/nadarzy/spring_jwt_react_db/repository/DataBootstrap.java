package com.nadarzy.spring_jwt_react_db.repository;

import com.nadarzy.spring_jwt_react_db.domain.RoleEnum;
import com.nadarzy.spring_jwt_react_db.domain.User;
import com.nadarzy.spring_jwt_react_db.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/** Created by Julian Nadarzy on 26/09/2021 */
@Component
public class DataBootstrap implements CommandLineRunner {
  private final UserService userService;

  private final RoleRepository roleRepository;

  public DataBootstrap(UserService userService, RoleRepository roleRepository) {
    this.userService = userService;
    this.roleRepository = roleRepository;
  }

  @Override
  public void run(String... args) throws Exception {
    if (userService.getUsers().size() == 0) {
      loadUsers();
    }
  }

  private void loadUsers() {
    User user = new User();
    user.setName("John Johnson");
    user.setUsername("john32");
    user.setEmail("john@mail.box");
    user.setPassword("1234");

    userService.saveUser(user);
    userService.addRoleToUser(user.getUsername(), RoleEnum.ROLE_USER);
  }
}
