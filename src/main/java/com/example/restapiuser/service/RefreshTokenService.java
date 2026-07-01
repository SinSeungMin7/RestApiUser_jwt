package com.example.restapiuser.service;

import com.example.restapiuser.config.JwtProperties;
import com.example.restapiuser.entity.RefreshTokenEntity;
import com.example.restapiuser.entity.UserEntity;
import com.example.restapiuser.exception.ApiException;
import com.example.restapiuser.repository.RefreshTokenRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@Transactional
public class RefreshTokenService {
    // Refresh Token을 생성, DB 저장, 검증, 폐기하는 핵심 서비스
    // 주의사황 : 이 클래스가 만드는 Refresh Token은 JWT가 아니라 랜덤 문자열이라는 것입니다.
    //
    //Access Token
    //→ JwtService가 생성
    //→ JWT 형식
    //→ DB에 저장하지 않음
    //→ API 인증에 사용
    //
    //Refresh Token
    //→ RefreshTokenService가 생성
    //→ 랜덤 문자열
    //→ DB에는 해시값 저장
    //→ Access Token 재발급에 사용

    // REFRESH_TOKEN DB 테이블
    //- id
    //- user_id
    //- token_hash
    //- expires_at
    //- revoked
    //- created_at
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;
    private final SecureRandom secureRandom = new SecureRandom(); // 보안 목적의 난수 생성

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtProperties jwtProperties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtProperties = jwtProperties;
    }

    // Refresh Token 생성
    public String createRefreshToken(UserEntity user) {
        // 기존 활성 Refresh Token 폐기 - 사용자 1명당 활성 Refresh Token 1개만 허용하는 구조입
        revokeAllActiveTokens(user);

        // 랜덤 Refresh Token 생성
        // rawToken은 실제로 클라이언트에게 전달되는 Refresh Token 원문  : L4VzPCdPLq2Ml7qYw3zM9smR9cdg2X4p...
        String rawToken = createRandomToken();

        // DB에는 원문이 아니라 해시 저장 : DB가 유출되어도 Refresh Token 원문을 바로 알 수 없게 하기 위함
        // 다만 비밀번호는 보통 BCrypt, Argon2 같은 느린 해시를 쓰고, 토큰은 충분히 랜덤하므로 SHA-256 해시 저장 방식도 자주 사용
        RefreshTokenEntity refreshToken = new RefreshTokenEntity(
                user,
                sha256(rawToken),
                LocalDateTime.now().plusDays(jwtProperties.refreshTokenDays())   // 만료 시간 저장 :refresh-token-days: 7 일
        );
        refreshTokenRepository.save(refreshToken);
        return rawToken;
    }

    // Refresh Token 검증
    // 이 메서드는 Refresh Token으로 새 Access Token을 발급받을 때 사용
    @Transactional(readOnly = true)  // 읽기 전용 트랜잭션 이 메서드는 DB를 수정하지 않고 조회만 합니다.
    public UserEntity verifyAndGetUser(String rawToken) {
        // 전달받은 토큰을 해시로 변환 후 조회
        // 클라이언트가 보낸 Refresh Token 원문을 SHA-256 해시로 바꿉니다.
        // 그 다음 DB의 tokenHash와 비교합니다.
        RefreshTokenEntity refreshToken = refreshTokenRepository.findByTokenHash(sha256(rawToken))
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "유효하지 않은 Refresh Token입니다")); // HTTP 상태는 401 Unauthorized

        // 폐기된 토큰인지 확인
            // 로그아웃한 토큰
            // 재발급에 이미 사용된 토큰
            // 새 로그인으로 인해 이전 토큰이 폐기된 경우
        // DB에 토큰이 존재하더라도 revoked가 true이면 사용할 수 없습니다.
        if (refreshToken.isRevoked()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "이미 폐기된 Refresh Token입니다");
        }

        // 만료 여부 확인
        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "만료된 Refresh Token입니다");
        }

        // 사용자 계정 활성화 여부 확인 :관리자가 사용자를 비활성화한 경우
        if (!refreshToken.getUser().isEnabled()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "비활성화된 사용자입니다");
        }

        // 검증 성공 시 사용자 반환
        return refreshToken.getUser();
    }

    // 5. Refresh Token 폐기
    public void revoke(String rawToken) {
        // 토큰이 있으면 폐기
        // 토큰이 없으면 조용히 종료
        refreshTokenRepository.findByTokenHash(sha256(rawToken))
                .ifPresent(RefreshTokenEntity::revoke);   // 토큰이 없어도 예외를 발생시키지 않습니다
    }

    // 특정 사용자의 아직 폐기되지 않은 Refresh Token을 모두 폐기
    public void revokeAllActiveTokens(UserEntity user) {
        refreshTokenRepository.findByUserAndRevokedFalse(user)
                .forEach(RefreshTokenEntity::revoke);
    }

    // 만료된 토큰 삭제
    // @Scheduled(cron = "0 0 3 * * *") : 추가하면  매일 새벽 3시에 만료 토큰을 삭제할 수 있습니다
    public void deleteExpiredTokens() {
        refreshTokenRepository.deleteByExpiresAtBefore(LocalDateTime.now());
    }

     // 랜덤 토큰 생성
    private String createRandomToken() {
        // 64바이트 랜덤값 생성
        byte[] bytes = new byte[64];
        secureRandom.nextBytes(bytes);
        // URL-safe Base64 인코딩 : URL이나 JSON에서 사용하기 편한 문자 사용
         // + 대신 -,  / 대신 _,  padding = 제거
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // SHA-256 해시 생성 : 8b7f3c8a0b6d9e2f...
    private String sha256(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 알고리즘을 사용할 수 없습니다", e);
        }
    }
}
