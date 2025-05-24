package com.project.news.oauth2.handler;

import com.project.news.common.exception.ConflictException;
import com.project.news.common.util.CookieUtil;
import com.project.news.jwt.dto.JwtResponseDto;
import com.project.news.oauth2.Entity.TokenProvider;
import com.project.news.oauth2.dto.CustomOAuthUser;
import com.project.news.oauth2.service.UserTokenHelper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Collection;
import java.util.Iterator;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserTokenHelper userTokenHelper;

    @Value("${service.url.client}")
    String clientIp;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        try {
            CustomOAuthUser customUserDetails = (CustomOAuthUser) authentication.getPrincipal();

            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
            GrantedAuthority auth = iterator.next();
            String role = auth.getAuthority();

            // 토근 발급 및 Redis에 RefreshToken 저장
            JwtResponseDto token = userTokenHelper.generateAndStoreToken(TokenProvider.SERVER, customUserDetails.getEmail(), role);

            log.info("accesstoken: {}", token.getAccessToken());
            response.addCookie(CookieUtil.createCookie("accessToken", token.getAccessToken(), 24 * 60 * 60));
            response.addCookie(CookieUtil.createCookie("refreshToken", token.getRefreshToken(), 24 * 60 * 60));
            response.sendRedirect(clientIp+"/oauth2/redirect");

        } catch (ConflictException ex) {
            // 예외 발생 시 클라이언트에 에러 메시지를 전달하기 위해 리디렉트
            response.sendRedirect(clientIp + "/error?message=" + URLEncoder.encode(ex.getMessage(), "UTF-8"));
        }
    }
}