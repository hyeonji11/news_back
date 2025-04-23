package com.project.news.oauth2.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class CustomOAuthUser implements OAuth2User {

    private final UserDto userDTO;

    public CustomOAuthUser(UserDto userDTO) {
        this.userDTO = userDTO;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userDTO.getProvider();
            }
        });

        return collection;
    }

    @Override
    public String getName() {
        return userDTO.getName();
    }

    public String getProvider() {
        return userDTO.getProvider();
    }

    public String getEmail() {
        return userDTO.getEmail();
    }

    public String getProfileImage() {
        return userDTO.getProfileImage();
    }
}
