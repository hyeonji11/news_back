package com.project.news.user.controller;

import com.project.news.jwt.dto.JwtResponseDto;
import com.project.news.user.dto.LoginRequestDto;
import com.project.news.user.dto.SignupRequestDto;
import com.project.news.user.dto.TokenRefreshRequestDto;
import com.project.news.user.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<?> joinUser(@RequestBody @Valid SignupRequestDto request) {
        Long result = userService.signup(request);

        return new ResponseEntity(result, HttpStatus.CREATED);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequestDto request) {
        JwtResponseDto result = userService.login(request);

        return new ResponseEntity(result, HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        userService.logout(request);

        return new ResponseEntity("로그아웃 성공", HttpStatus.OK);
    }


    @PostMapping("/withdraw")
    public ResponseEntity<?> withdraw(HttpServletRequest request) {
        return userService.withdraw(request);
    }

    @PostMapping("/test")
    public ResponseEntity<?> test(HttpServletRequest request) {
        System.out.println("테스트");
        return new ResponseEntity<>("테스트 성공", HttpStatus.OK);
    }

    @PostMapping("/reissue")
    public ResponseEntity reissue(@RequestBody TokenRefreshRequestDto request) {

        JwtResponseDto response = null;
        try {
            response = userService.reissueToken(request);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage() , HttpStatus.UNAUTHORIZED);
        }

        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
