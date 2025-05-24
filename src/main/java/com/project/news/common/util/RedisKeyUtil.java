package com.project.news.common.util;

import com.project.news.oauth2.Entity.TokenProvider;
import com.project.news.oauth2.Entity.TokenType;

public class RedisKeyUtil {

    public static String generateTokenKey(TokenType type, TokenProvider provider, String email) {
        return String.format("%s:%s:%s", type.name(), provider.name(), email);
    }
}
