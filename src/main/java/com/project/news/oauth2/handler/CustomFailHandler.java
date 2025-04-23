package com.project.news.oauth2.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;

@Component
public class CustomFailHandler implements AuthenticationFailureHandler {

    @Value("{service.url.client}")
    String clientUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = null;

        // 예외 메시지를 확인하여 적절한 메시지를 설정
        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2AuthenticationException oauthException = (OAuth2AuthenticationException) exception;
            errorMessage = oauthException.getMessage();
            if ("conflict".equals(oauthException.getError().getErrorCode())) {
                errorMessage = oauthException.getMessage();
            } else if ("unsupported_social_login".equals(oauthException.getError().getErrorCode())) {
                errorMessage = oauthException.getMessage();
            }
        }

        // 에러 메시지를 클라이언트에 전달하기 위해 리디렉트
        response.sendRedirect(clientUrl + "/error?message=" + URLEncoder.encode(errorMessage, "UTF-8"));
    }
}