package com.project.news.jwt;

import com.project.news.user.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class UserDetailsImpl implements UserDetails {

    private final User user;

    public UserDetailsImpl(User user) {
        this.user = user;
    }

    public Long getUserId() {
        return user.getId();
    }

//    public Role getRole() {
//        return member.getRole();
//    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
//        authorities.add(() -> member.getRole().getRole()); // key: ROLE_권한
        return authorities;
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }


    // == 세부 설정 == //
    @Override
    public boolean isAccountNonExpired() { // 계정의 만료 여부
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // 계정의 잠김 여부
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // 비밀번호 만료 여부
        return true;
    }

    @Override
    public boolean isEnabled() { // 계정의 활성화 여부
        return true;
    }
}