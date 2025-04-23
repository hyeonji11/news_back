package com.project.news.oauth2.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserDto {
    private String name;
    private String provider;
    private String email;
    private String profileImage;
}
