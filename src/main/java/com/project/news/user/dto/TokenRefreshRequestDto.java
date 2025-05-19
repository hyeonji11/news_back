package com.project.news.user.dto;

public record TokenRefreshRequestDto(String accessToken, String refreshToken) {
}
