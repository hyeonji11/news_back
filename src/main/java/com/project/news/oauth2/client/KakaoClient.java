package com.project.news.oauth2.client;

import com.project.news.oauth2.dto.KakaoIdResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name="${feign.kakao.name}", url="${feign.kakao.url}")
public interface KakaoClient {

    @PostMapping("/v1/user/logout")
    public KakaoIdResponse logout(@RequestHeader("Authorization") String accessToken);

    @PostMapping("/v1/user/unlink")
    public KakaoIdResponse unlink(@RequestHeader("Authorization") String accessToken);
}
