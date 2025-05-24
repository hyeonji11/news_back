package com.project.news.oauth2.Entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Provider {
    GOOGLE("google"),
    KAKAO("kakao");

    @Getter
    private final String value;
}
