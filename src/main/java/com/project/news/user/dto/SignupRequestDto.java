package com.project.news.user.dto;

import com.project.news.user.entity.User;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequestDto {

    private String email;

    private String nickname;

    private String password;

    private String imageUrl;

    @Builder
    public SignupRequestDto(String email, String nickname, String password, String imageUrl) {
        this.email = email;
        this.nickname = nickname;
        this.password = password;
        this.imageUrl = imageUrl;
    }


    public User convertToUser() {
        return User.builder()
                .email(email)
                .nickname(nickname)
                .password(password)
                .imageUrl(imageUrl)
                .build();
    }

}
