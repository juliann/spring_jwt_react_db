package com.nadarzy.spring_jwt_react_db.service;

import com.nadarzy.spring_jwt_react_db.domain.Role;
import com.nadarzy.spring_jwt_react_db.domain.RoleEnum;
import com.nadarzy.spring_jwt_react_db.domain.User;

import java.util.List;

public interface UserService {

  User saveUser(User user);

  Role saveRole(Role role);

  void addRoleToUser(String username, RoleEnum roleName);

  User getUser(String username);

  List<User> getUsers();
}
