package com.project.news.oauth2.service;

import com.project.news.common.service.RedisService;
import com.project.news.common.util.RedisKeyUtil;
import com.project.news.oauth2.Entity.Provider;
import com.project.news.oauth2.Entity.TokenProvider;
import com.project.news.oauth2.Entity.TokenType;
import com.project.news.oauth2.dto.*;
import com.project.news.user.entity.User;
import com.project.news.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final RedisService redisService;
    private final long ACCESS_TOKEN_EXPIRATION = 6 * 60 * 60 * 1000L; // 6시간

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String oauth2AccessToken = userRequest.getAccessToken().getTokenValue();

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;

        if (registrationId.equals(Provider.GOOGLE.getValue())) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals(Provider.KAKAO.getValue())) {
            oAuth2Response = new KakaoResponse(oAuth2User.getAttributes());
        } else {
            throw new OAuth2AuthenticationException(new OAuth2Error("unsupported_social_login"), "허용되지 않은 소셜 로그인입니다: " + registrationId);
        }

        String socialName = oAuth2Response.getProvider();
        Optional<User> userOptional = userRepository.findByEmail(oAuth2Response.getEmail());

        if (userOptional.isPresent()) {
            log.info("이미 가입한 계정");
            User user = userOptional.get();
            if (user.getProvider() == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error("conflict"), "해당 메일로 가입된 일반 계정이 존재합니다: " + oAuth2Response.getEmail());
            }
            if (!user.getProvider().equals(socialName)) {
                throw new OAuth2AuthenticationException(new OAuth2Error("conflict"), "이미 다른 소셜 계정으로 가입된 이메일입니다: " + oAuth2Response.getEmail());
            }
//            user.setImageUrl(oAuth2Response.getProfileUrl());
//            user.setNickName(oAuth2Response.getName());
        } else {
            User user = User.builder()
                    .email(oAuth2Response.getEmail())
                    .provider(socialName)
                    .imageUrl(oAuth2Response.getProfileUrl())
                    .nickname(oAuth2Response.getName())
                    .build();
            userRepository.save(user);
            log.info("가입하지 않은 계정 가입 완료 : {}", user.getEmail());
        }

        redisService.setValuesWithTimeout(RedisKeyUtil.generateTokenKey(TokenType.AT, TokenProvider.OAUTH2, oAuth2Response.getEmail()), oauth2AccessToken, ACCESS_TOKEN_EXPIRATION);
        log.info("oauth2 access token 저장 key email : {}", oAuth2Response.getEmail());

        UserDto userDTO = UserDto.builder()
                .provider(socialName)
                .name(oAuth2Response.getName())
                .email(oAuth2Response.getEmail())
                .profileImage(oAuth2Response.getProfileUrl())
                .build();

        return new CustomOAuthUser(userDTO);
    }
}