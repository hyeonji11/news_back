package com.project.news.user.service;

import com.project.news.user.dto.SignupRequestDto;
import com.project.news.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DuplicateKeyException;

import static org.junit.jupiter.api.Assertions.*;

@Transactional
@SpringBootTest
class UserServiceTest {

    @Autowired
    UserService userService;

    @Autowired
    UserRepository userRepository;

    @Test
    @DisplayName("정상 가입 테스트")
    public void signUp() {
        SignupRequestDto request = SignupRequestDto.builder()
                .email("test01@test.com")
                .password("1234")
                .nickname("test")
                .imageUrl("image")
                .build();

        Long result = userService.signup(request);

        assertEquals(result, userRepository.findByEmail("test01@test.com").get().getId());
    }

    @Test
    @DisplayName("중복 가입 테스트")
    public void signupConflictEmail() {
        SignupRequestDto request = SignupRequestDto.builder()
                .email("test01@test.com")
                .password("1234")
                .nickname("test")
                .imageUrl("image")
                .build();

        SignupRequestDto request2 = SignupRequestDto.builder()
                .email("test01@test.com")
                .password("4321")
                .nickname("test02")
                .imageUrl("image02")
                .build();

        Long result = userService.signup(request);

        assertThrows(DuplicateKeyException.class, () -> userService.signup(request2));
    }
}