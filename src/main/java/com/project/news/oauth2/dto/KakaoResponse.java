package com.project.news.oauth2.dto;

import com.project.news.oauth2.Entity.Provider;

import java.util.Map;

public class KakaoResponse implements OAuth2Response {

    private Map<String, Object> attribute;
    private Map<String, Object> kakaoAccountAttributes;
    private Map<String, Object> profileAttributes;

    public KakaoResponse(Map<String, Object> attribute) {
        this.attribute = attribute;
        this.kakaoAccountAttributes = (Map<String, Object>) attribute.get("kakao_account");
        this.profileAttributes = (Map<String, Object>) kakaoAccountAttributes.get("profile");
    }

    @Override
    public String getProvider() {
        return Provider.KAKAO.getValue();
    }

    @Override
    public String getProviderId() {
        return attribute.get("id").toString();
    }

    @Override
    public String getEmail() {
        return kakaoAccountAttributes.get("email").toString();
    }

    @Override
    public String getName() {
        return profileAttributes.get("nickname").toString();
    }

    @Override
    public String getProfileUrl() {
        return profileAttributes.get("profile_image_url").toString();
    }
}