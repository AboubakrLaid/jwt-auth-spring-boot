package com.geoalert.auth.Controller;


import com.geoalert.auth.dto.*;
import com.geoalert.auth.security.JWTUtil;
import com.geoalert.auth.service.AuthService;
import com.geoalert.auth.service.UserInfoConfigManager;
import com.geoalert.auth.utils.ResponseHandler;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    JWTUtil jwtUtil;

    @Autowired
    AuthService authService;

    @Autowired
    AuthenticationManager authenticationManager;
    
    @Autowired
    private UserInfoConfigManager userInfoConfigManager;

    @PostMapping("/register")
    public ResponseEntity<Object> register(@Valid @RequestBody RegisterDTO registerDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseHandler.generateValidationErrorResponse(bindingResult, HttpStatus.BAD_REQUEST);
        }
        if (authService.emailExists(registerDTO.getEmail())) {
            return ResponseHandler.generateResponse("Email is already in use", HttpStatus.BAD_REQUEST, null);
        }

        RegisterResponse response = authService.register(registerDTO);
        return ResponseHandler.generateResponse("User registered successfully", HttpStatus.OK, response);
    }


    @PostMapping("/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginDTO loginDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseHandler.generateValidationErrorResponse(bindingResult, HttpStatus.BAD_REQUEST);
        }
        try {
            Authentication authenticate = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword()));
            UserDetails userDetails = userInfoConfigManager.loadUserByUsername(loginDTO.getEmail());
            String jwt = jwtUtil.generateToken(userDetails.getUsername());
            String refreshToken = jwtUtil.generateRefreshToken(userDetails.getUsername());
            LoginResponse loginResponse = LoginResponse
                    .builder()
                    .accessToken(jwt)
                    .refreshToken(refreshToken)
                    .build();
            return ResponseHandler.generateResponse("User logged in successfully", HttpStatus.OK, loginResponse);
        }
        catch (Exception e)
        {
            return ResponseHandler.generateErrorResponse("Incorrect email or password", HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<Object> refreshAccessToken(@Valid @RequestBody RefreshTokenDTO refreshTokenDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseHandler.generateValidationErrorResponse(bindingResult, HttpStatus.BAD_REQUEST);
        }

        String refreshToken = refreshTokenDTO.getRefreshToken();

        if (refreshToken == null || !jwtUtil.validateRefreshToken(refreshToken)) {
            return ResponseHandler.generateErrorResponse("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }

        String email = jwtUtil.extractEmail(refreshToken, true);
        RefreshTokenResponse refreshTokenResponse = new RefreshTokenResponse(jwtUtil.generateToken(email));

        return ResponseHandler.generateResponse("Token refreshed successfully", HttpStatus.OK, refreshTokenResponse);
    }


    @GetMapping("/protected")
    public ResponseEntity<Object> getProtectedData() {
        return ResponseHandler.generateResponse("Access granted to protected resource", HttpStatus.OK,
                Map.of("data", "This is a protected endpoint"));
    }
}
