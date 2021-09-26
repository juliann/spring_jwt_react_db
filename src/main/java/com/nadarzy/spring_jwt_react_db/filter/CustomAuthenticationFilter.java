package com.nadarzy.spring_jwt_react_db.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nadarzy.spring_jwt_react_db.service.UserDetailsImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/** Created by Julian Nadarzy on 26/09/2021 */
@Slf4j
@PropertySource("classpath:application.properties")
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  //  @Value("${com.nadarzy.app.jwtSecret}")
  private String jwtSecret = "password";

  //  @Value("${com.nadarzy.app.jwtExpirationMs}")
  private static int jwtExpirationMs = 3200000;

  //  @Value("${com.nadarzy.app.jwtRefreshtExpirationMs}")
  private static int jwtRefreshExpirationMs = 1000000000;

  private final AuthenticationManager authenticationManager;

  public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    log.error(request.getMethod());
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    log.info("Username is: {}", username);
    log.info("Password is: {}", password);
    var usernamePasswordAuthenticationToken =
        new UsernamePasswordAuthenticationToken(username, password);
    return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
  }

  @Override
  protected void successfulAuthentication(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain chain,
      Authentication authentication)
      throws IOException, ServletException {
    UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();
    Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes(StandardCharsets.UTF_8));
    String accessToken =
        JWT.create()
            .withSubject(user.getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis() + jwtExpirationMs))
            .withIssuer(request.getRequestURL().toString())
            .withClaim(
                "roles",
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
            .sign(algorithm);

    String refreshToken =
        JWT.create()
            .withSubject(user.getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis() + jwtRefreshExpirationMs))
            .withIssuer(request.getRequestURL().toString())
            .sign(algorithm);

    //    response.setHeader("access_token", accessToken);
    //    response.setHeader("refresh_token", refreshToken);

    Map<String, String> tokens = new HashMap<>();
    tokens.put("access_token", accessToken);
    tokens.put("refresh_token", refreshToken);
    response.setContentType(APPLICATION_JSON_VALUE);
    new ObjectMapper().writeValue(response.getOutputStream(), tokens);
  }
}
