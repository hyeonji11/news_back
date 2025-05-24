package com.project.news.oauth2.service;

import com.project.news.common.service.RedisService;
import com.project.news.common.util.RedisKeyUtil;
import com.project.news.jwt.JwtProvider;
import com.project.news.jwt.dto.JwtResponseDto;
import com.project.news.oauth2.Entity.TokenProvider;
import com.project.news.oauth2.Entity.TokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserTokenHelper {
    private final JwtProvider jwtProvider;
    private final RedisService redisService;

    private final Long refreshTokenValidityInMilliseconds = 7 * 24 * 60 * 60 * 1000L; // 7일

    public JwtResponseDto generateAndStoreToken(TokenProvider provider, String email, String role) {
        String redisKey = RedisKeyUtil.generateTokenKey(TokenType.RT, provider, email);;
        redisService.deleteValues(redisKey);

        JwtResponseDto tokenDto = jwtProvider.createToken(email, role);
        redisService.setValuesWithTimeout(redisKey, tokenDto.getRefreshToken(), refreshTokenValidityInMilliseconds);
        return tokenDto;
    }
}
