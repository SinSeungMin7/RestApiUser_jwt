package com.example.restapiuser.service;

import com.example.restapiuser.config.JwtProperties;
import com.example.restapiuser.entity.UserEntity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Service
public class JwtService {
    // Access Token을 생성하는 서비스 클래스입니다.
    //  Refresh Token은 여기서 만들지 않습니다.
    // 이 클래스는 오직 JWT Access Token 생성과 Access Token 만료 시간 계산을 담당
    // 1. 현재 시간 계산
    //2. Access Token 만료 시간 계산
    //3. JWT payload에 들어갈 claim 구성
    //4. HS256 방식으로 JWT 서명
    //5. 최종 Access Token 문자열 반환

    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;

    public JwtService(JwtEncoder jwtEncoder, JwtProperties jwtProperties) {
        this.jwtEncoder = jwtEncoder;
        this.jwtProperties = jwtProperties;
    }

    public String createAccessToken(UserEntity user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(jwtProperties.accessTokenMinutes(), ChronoUnit.MINUTES);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .subject(user.getUserid())
                .claim("username", user.getUsername())
                .claim("roles", List.of("ROLE_" + user.getRole().name()))
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public long getAccessTokenExpiresInSeconds() {
        return jwtProperties.accessTokenMinutes() * 60;
    }
}
