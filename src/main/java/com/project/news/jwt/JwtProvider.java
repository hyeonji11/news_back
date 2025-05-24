package com.project.news.jwt;

import com.project.news.common.exception.JwtAuthenticationException;
import com.project.news.common.service.RedisService;
import com.project.news.common.util.UUIDUtil;
import com.project.news.jwt.dto.JwtResponseDto;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Component
@Transactional(readOnly = true)
public class JwtProvider implements InitializingBean {

    private final UserDetailsServiceImpl userDetailsService;
    private final RedisService redisService;

    private static final String AUTHORITIES_KEY = "role";
    private static final String EMAIL_KEY = "email";

    private final String secretKey;
    private static Key signingKey;

    private final Long accessTokenValidityInMilliseconds = 60 * 60 * 1000L; // 60분
    private final Long refreshTokenValidityInMilliseconds = 7 * 24 * 60 * 60 * 1000L; // 7일

    public JwtProvider(
            UserDetailsServiceImpl userDetailsService,
            RedisService redisService,
            @Value("${jwt.secret}") String secretKey) {
        this.userDetailsService = userDetailsService;
        this.redisService = redisService;
        this.secretKey = secretKey;
    }

    // 시크릿 키 설정
    @Override
    public void afterPropertiesSet() {
        byte[] secretKeyBytes = Decoders.BASE64.decode(secretKey);
        signingKey = Keys.hmacShaKeyFor(secretKeyBytes);
    }

    /**
     * 액세스 토큰과 리프레시 토큰을 생성합니다.
     *
     * @param email       사용자 이메일
     * @param authorities 사용자 권한
     * @return JwtResponseDTO 액세스 토큰과 리프레시 토큰이 포함된 DTO
     */
    @Transactional
    public JwtResponseDto createToken(String email, String authorities){
        Long now = System.currentTimeMillis();

        String accessToken = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS512")
                .setExpiration(new Date(now + accessTokenValidityInMilliseconds))
                .setSubject("access-token")
                .claim(EMAIL_KEY, email)
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(signingKey, SignatureAlgorithm.HS512)
                .compact();

        String refreshToken = UUIDUtil.getUUID();

        return JwtResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * 토큰으로부터 Claims 객체를 추출합니다.
     *
     * @param token JWT 토큰
     * @return Claims 토큰에서 추출된 클레임 정보
     */
    public Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) { // Access Token
            return e.getClaims();
        }
    }

    /**
     * 토큰으로부터 인증 정보를 추출합니다.
     *
     * @param token JWT 토큰
     * @return Authentication 인증 정보
     */
    public Authentication getAuthentication(String token) {
        String email = getClaims(token).get(EMAIL_KEY).toString();
        UserDetailsImpl userDetailsImpl = userDetailsService.loadUserByUsername(email);
        return new UsernamePasswordAuthenticationToken(userDetailsImpl, "", userDetailsImpl.getAuthorities());
    }

    /**
     * 토큰의 만료 시간을 반환합니다.
     *
     * @param token JWT 토큰
     * @return long 토큰 만료 시간 (밀리초 단위)
     */
    public long getTokenExpirationTime(String token) {
        return getClaims(token).getExpiration().getTime();
    }

    /**
     * 리프레시 토큰의 유효성을 검증합니다.
     *
     * @param refreshToken 리프레시 토큰
     * @return boolean 유효한 경우 true, 그렇지 않으면 false
     */
    public boolean validateRefreshToken(String refreshToken) {
        String redisValue = redisService.getValues(refreshToken);
        if ("delete".equals(redisValue)) { // 회원 탈퇴 여부 확인
            return false;
        }
        return true;
    }

    /**
     * HTTP 요청의 Authorization 헤더에서 JWT 토큰을 추출합니다.
     *
     * @param httpServletRequest HttpServletRequest 객체
     * @return String 추출된 토큰 또는 null
     */
    public String resolveToken(HttpServletRequest httpServletRequest) {
        String bearerToken = httpServletRequest.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * 액세스 토큰의 유효성을 검증합니다.
     *
     * @param accessToken 액세스 토큰
     * @throws JwtAuthenticationException 토큰이 유효하지 않은 경우 예외 발생
     */
    public void validateAccessToken(String accessToken) throws JwtAuthenticationException {
        try {
            log.info("Validating access token:{}", accessToken);
            if (redisService.getValues(accessToken) != null // NPE 방지
                    && redisService.getValues(accessToken).equals("logout")) { // 로그아웃 했을 경우
                throw new JwtAuthenticationException("로그아웃된 토큰입니다.");
            }

            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(accessToken);

        } catch (SignatureException e) {
            log.error("Invalid JWT signature.");
            throw new JwtAuthenticationException("Invalid JWT signature.");
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token.");
            throw new JwtAuthenticationException("Invalid JWT token.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token.");
            throw new JwtAuthenticationException("Expired JWT token.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token.");
            throw new JwtAuthenticationException("Unsupported JWT token.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty.");
            throw new JwtAuthenticationException("JWT claims string is empty.");
        } catch (NullPointerException e) {
            log.error("JWT Token is empty.");
            throw new JwtAuthenticationException("JWT Token is empty.");
        }
    }

    /**
     * 토큰이 만료되었는지 확인합니다.
     *
     * @param token JWT 토큰
     * @return boolean 만료된 경우 true, 그렇지 않으면 false
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getClaims(token).getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            return true; // 만료된 것으로 간주
        }
    }
}