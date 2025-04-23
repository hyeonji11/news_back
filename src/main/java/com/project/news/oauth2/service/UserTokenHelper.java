package com.project.news.oauth2.service;

import com.project.news.common.service.RedisService;
import com.project.news.jwt.JwtProvider;
import com.project.news.jwt.dto.JwtResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserTokenHelper {
    private final JwtProvider jwtProvider;
    private final RedisService redisService;

    public JwtResponseDto generateAndStoreToken(String provider, String email, String role) {
        String redisKey = "RT(" + provider + "):" + email;
        redisService.deleteValues(redisKey);

        JwtResponseDto tokenDto = jwtProvider.createToken(email, role);
        redisService.setValuesWithTimeout(redisKey, tokenDto.getRefreshToken(), jwtProvider.getTokenExpirationTime(tokenDto.getRefreshToken()));
        return tokenDto;
    }
}
