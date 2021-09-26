package com.nadarzy.spring_jwt_react_db.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nadarzy.spring_jwt_react_db.domain.Role;
import com.nadarzy.spring_jwt_react_db.domain.RoleEnum;
import com.nadarzy.spring_jwt_react_db.domain.User;
import com.nadarzy.spring_jwt_react_db.service.UserService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/** Created by Julian Nadarzy on 26/09/2021 */
@RestController
@RequestMapping("/api")
@Slf4j
public class UserController {

  //  @Value("${com.nadarzy.app.jwtSecret}")
  private String jwtSecret = "password";

  //  @Value("${com.nadarzy.app.jwtExpirationMs}")
  private static int jwtExpirationMs = 32000;

  //  @Value("${com.nadarzy.app.jwtRefreshtExpirationMs}")
  private static int jwtRefreshExpirationMs = 1000000000;

  private final UserService userService;

  public UserController(UserService userService) {
    this.userService = userService;
  }

  @GetMapping("/users")
  public ResponseEntity<List<User>> getUsers() {

    return ResponseEntity.ok().body(userService.getUsers());
  }

  @PostMapping("/user/save")
  public ResponseEntity<User> saveUser(@RequestBody User user) {
    URI uri =
        URI.create(
            ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/api/user/save)")
                .toUriString());
    return ResponseEntity.created(uri).body(userService.saveUser(user));
    //    return new ResponseEntity<>(user, HttpStatus.CREATED);
  }

  @PostMapping("/role/addtouser")
  public ResponseEntity<Void> addRoleToUser(@RequestBody RoleToUserForm roleToUserForm) {
    userService.addRoleToUser(roleToUserForm.getUsername(), roleToUserForm.getRoleName());
    return ResponseEntity.ok().build();
  }

  @GetMapping("/token/refresh")
  public void refreshToken(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String authorizationHeader = request.getHeader(AUTHORIZATION);
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

      try {
        String refreshToken = authorizationHeader.substring("Bearer ".length());
        Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes(StandardCharsets.UTF_8));
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = jwtVerifier.verify(refreshToken);
        String username = decodedJWT.getSubject();
        User user = userService.getUser(username);

        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

        String accessToken =
            JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getRoles().stream().map(Role::getName).toList())
                .sign(algorithm);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);

      } catch (Exception e) {

        log.error("error logging in" + e.getMessage());
        response.setHeader("error", e.getMessage());
        response.setStatus(FORBIDDEN.value());
        //          response.sendError(FORBIDDEN.value());
        Map<String, String> error = new HashMap<>();
        error.put("error_message", e.getMessage());
        //          tokens.put("refresh_token", refreshToken);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
      }
    } else {
      throw new RuntimeException("REFRESH TOKEN MISSING");
    }
  }
}

@Data
class RoleToUserForm {
  private String username;
  private RoleEnum roleName;
}
