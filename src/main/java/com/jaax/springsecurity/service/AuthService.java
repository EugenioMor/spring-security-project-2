package com.jaax.springsecurity.service;

import com.jaax.springsecurity.controller.models.AuthResponse;
import com.jaax.springsecurity.controller.models.AuthenticationRequest;
import com.jaax.springsecurity.controller.models.RegisterRequest;

public interface AuthService {

    AuthResponse register(RegisterRequest request);
    AuthResponse authenticate(AuthenticationRequest request);
}
