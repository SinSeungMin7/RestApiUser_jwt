package com.example.restapiuser.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

// application.yml 설정 파일에서 app.jwt로 시작하는 값을 읽어오겠다
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        String issuer,
        String secret,
        long accessTokenMinutes,
        long refreshTokenDays
) {
}
