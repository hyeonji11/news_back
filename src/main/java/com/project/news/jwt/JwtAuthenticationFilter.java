package com.project.news.jwt;

import com.project.news.common.exception.JwtAuthenticationException;
import com.project.news.jwt.handler.JwtExceptionHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final JwtExceptionHandler jwtExceptionHandler;
    private static final AntPathMatcher pathMatcher = new AntPathMatcher();
    private static final List<String> EXCLUDED_URLS = Arrays.asList(
            "/swagger-ui/**",
            "/v3/**",
            "/api/global/**",
            "/api/auth/signin",
            "/api/auth/signup",
            "/api/auth/reissue",
            "/images/**"
    );

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // 제외할 경로일 경우 필터 건너뛰기
        String requestURI = request.getRequestURI();
        if (EXCLUDED_URLS.stream().anyMatch(pattern -> pathMatcher.match(pattern, requestURI))) {
            filterChain.doFilter(request, response);
            return;
        }

        // Access Token 추출
        String accessToken = jwtProvider.resolveToken(request);

        try {
            if (accessToken == null) {
                throw new JwtAuthenticationException("토큰이 존재하지 않습니다.");
            }

            // 정상 토큰인지 검사
            jwtProvider.validateAccessToken(accessToken);
            Authentication authentication = jwtProvider.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtAuthenticationException e) {
            SecurityContextHolder.clearContext();
            // 예외를 핸들러로 전달하기 위해 필터 체인 진행 차단
            jwtExceptionHandler.commence(request, response, e);
            return;
        }

        filterChain.doFilter(request, response);
    }
}