package com.project.news.oauth2.client;

import com.project.news.oauth2.dto.GoogleIdResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name="${feign.google.name}", url="${feign.google.url}")
public interface GoogleClient {

    @GetMapping("/tokeninfo")
    public GoogleIdResponse logout(@RequestParam("access_token") String accessToken);

    @PostMapping(value="/revoke", consumes = "application/x-www-form-urlencoded")
    public GoogleIdResponse unlink(@RequestBody String accessToken);

}
