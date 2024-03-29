package com.jaax.springsecurity.service;

import com.jaax.springsecurity.config.JwtService;
import com.jaax.springsecurity.controller.models.AuthResponse;
import com.jaax.springsecurity.controller.models.AuthenticationRequest;
import com.jaax.springsecurity.controller.models.RegisterRequest;
import com.jaax.springsecurity.entity.Role;
import com.jaax.springsecurity.entity.UserEntity;
import com.jaax.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthResponse register(RegisterRequest request) {
       var user = UserEntity.builder()
               .firstName(request.getFirstName())
               .lastName(request.getLastName())
               .email(request.getEmail())
               .password(passwordEncoder.encode(request.getPassword()))
               .role(Role.USER)
               .build();
       userRepository.save(user);
       var jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(jwtToken).build();
    }

    @Override
    public AuthResponse authenticate(AuthenticationRequest request) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findUserByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthResponse.builder().token(jwtToken).build();
    }
}
