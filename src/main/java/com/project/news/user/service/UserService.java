package com.project.news.user.service;

import com.project.news.common.entity.Response;
import com.project.news.common.service.RedisService;
import com.project.news.jwt.JwtProvider;
import com.project.news.jwt.dto.JwtResponseDto;
import com.project.news.oauth2.client.KakaoClient;
import com.project.news.oauth2.dto.KakaoIdResponse;
import com.project.news.user.dto.LoginRequestDto;
import com.project.news.user.dto.SignupRequestDto;
import com.project.news.user.entity.User;
import com.project.news.user.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final JwtProvider jwtProvider;
    private final RedisService redisService;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final KakaoClient kakaoClient;

    private final String SERVER = "Server";

    @Transactional
    public Long signup(SignupRequestDto requestDto) {
        userRepository.findByEmail(requestDto.getEmail())
                .ifPresent(existingMember -> {
                    throw new DuplicateKeyException("이미 존재하는 이메일입니다: " + requestDto.getEmail());
                });
        requestDto.setPassword(passwordEncoder.encode(requestDto.getPassword()));

        User user = requestDto.convertToUser();

        return userRepository.save(user).getId();
    }

    @Transactional
    public JwtResponseDto login(LoginRequestDto requestDto) {
        try {
            Authentication authentication = authenticateUser(requestDto.email(), requestDto.password());
            String email = authentication.getName();
            String authorities = extractAuthorities(authentication);

            // 토큰 생성 및 저장
            return generateAndStoreToken(SERVER, email, authorities);
        } catch (BadCredentialsException e) {
            e.printStackTrace();
            throw new BadCredentialsException("사용자 정보가 잘못 되었습니다.");
        }
    }

    @Transactional
    public void logout(HttpServletRequest request) {
        String email = invalidateToken(request.getHeader("Authorization").substring(7));

        // 소셜 로그인 유저인경우 oauth2 access token 삭제
        if(redisService.getValues("AT(oauth2):"+email) != null) {
            String socialAccessToken = redisService.getValues("AT(oauth2):"+email);
            kakaoLogout(socialAccessToken);
            log.info("kakao 로그아웃 성공");

            redisService.deleteValues("AT(oauth2):"+email);
        }

    }

    private String invalidateToken(String token) {
        long tokenExpiration = jwtProvider.getTokenExpirationTime(token);
        long expirationTime = tokenExpiration - new Date().getTime();

        String email = jwtProvider.getClaims(token).get("email").toString();

        // redis에 로그아웃 처리한 access token 저장
        redisService.setValuesWithTimeout(token, "logout", expirationTime);

        // redis에 저장된 refresh token 삭제
        if(redisService.getValues("RT("+SERVER+"):"+email) != null) {
            redisService.deleteValues("RT("+SERVER+"):"+email);
        }

        return email;
    }

    private void kakaoLogout(String accessToken) {
        try {
            KakaoIdResponse kakaoId = kakaoClient.logout("Bearer " + accessToken);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * 사용자 인증을 처리하고 인증된 Authentication 객체를 반환합니다.
     * SecurityContext에 인증 정보를 설정합니다.
     *
     * @param email 사용자의 이메일
     * @param password 사용자의 비밀번호
     * @return 인증된 사용자 정보가 담긴 Authentication 객체
     */
    private Authentication authenticateUser(String email, String password) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(email, password);
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }

    /**
     * JWT 토큰을 생성하고 리프레시 토큰을 Redis에 저장합니다.
     * 기존에 Redis에 리프레시 토큰이 있을 경우 삭제 후 새로운 토큰을 저장합니다.
     *
     * @param provider 서비스 제공자 정보 (예: "SERVER")
     * @param email 사용자 이메일
     * @param authorities 사용자의 권한 목록을 콤마로 연결한 문자열
     * @return 생성된 JWT 정보 (액세스 토큰 및 리프레시 토큰 포함)
     */
    public JwtResponseDto generateAndStoreToken(String provider, String email, String authorities) {
        String redisKey = "RT(" + provider + "):" + email;

        // Redis에 기존 RT가 있으면 삭제
        Optional.ofNullable(redisService.getValues(redisKey)).ifPresent(rt -> redisService.deleteValues(redisKey));

        // 새로운 토큰 생성 및 Redis에 저장
        JwtResponseDto tokenDto = jwtProvider.createToken(email, authorities);
        redisService.setValuesWithTimeout(redisKey, tokenDto.getRefreshToken(), jwtProvider.getTokenExpirationTime(tokenDto.getRefreshToken()));

        return tokenDto;
    }

    /**
     * Authentication 객체에서 사용자의 권한 목록을 추출하여 콤마로 구분된 문자열로 반환합니다.
     *
     * @param authentication 사용자 인증 정보가 담긴 Authentication 객체
     * @return 사용자의 권한 목록을 콤마로 연결한 문자열
     */
    private String extractAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }

    public ResponseEntity<?> withdraw(HttpServletRequest request) {
        String token = request.getHeader("Authorization").substring(7);
        String email = jwtProvider.getClaims(token).get("email").toString();

        User user = userRepository.findByEmail(email).orElse(null);

        // oauth2 계정일 때
        if(user.getProvider() != null) {
            String socialAccessToken = redisService.getValues("AT(oauth2):"+email);
            //oauth2 access token 만료 시 재 로그인 해야함
            if(socialAccessToken == null) {
                invalidateToken(token);
                // TODO : 로그인 필요 에러 날려서 화면에서 로그아웃 시키고 자동으로 로그인 화면으로 넘어가도록 조치
            } else {
                redisService.deleteValues("AT(oauth2):"+email);
                log.info("oauth2 Access Token Redis에서 삭제 : " + socialAccessToken);
            }
            kakaoUnlink(socialAccessToken);

            redisService.deleteValues("AT(oauth2):"+email);
            log.info("oauth2 Refresh Token Redis에서 삭제");
        }

        if(redisService.getValues("RT("+SERVER+"):"+email) != null) {
            redisService.deleteValues("RT("+SERVER+"):"+email);
        }

        userRepository.deleteById(user.getId());

        return new ResponseEntity<>(HttpStatus.OK);
    }

    public void kakaoUnlink(String accessToken) {
        KakaoIdResponse kakaoIdResponse = kakaoClient.unlink("Bearer " + accessToken);
        log.info("카카오 연결 끊기 성공 : ", kakaoIdResponse.id());

    }

}
