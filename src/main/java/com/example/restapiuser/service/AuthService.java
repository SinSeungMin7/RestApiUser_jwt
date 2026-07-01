package com.example.restapiuser.service;

import com.example.restapiuser.dto.AuthResponse;
import com.example.restapiuser.dto.LoginRequest;
import com.example.restapiuser.dto.TokenRefreshRequest;
import com.example.restapiuser.dto.UserResponse;
import com.example.restapiuser.entity.UserEntity;
import com.example.restapiuser.exception.ApiException;
import com.example.restapiuser.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AuthService {
    // AuthService는 아이디/비밀번호 인증은 AuthenticationManager에게 맡기고,
    // 인증 성공 후 JwtService와 RefreshTokenService를 이용해
    // Access Token과 Refresh Token을 발급하는 인증 흐름의 중심 서비스이다.
    // 아이디/비밀번호 검증
    //  → AuthenticationManager
    //  Access Token 생성
    //   → JwtService
    //  Refresh Token 생성/검증/폐기
    //   → RefreshTokenService
    //  응답 생성
    //   → AuthResponse

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(AuthenticationManager authenticationManager,
                       UserRepository userRepository,
                       JwtService jwtService,
                       RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.userid(), request.passwd())
        );
        // security/CustomUserDetailsService.java loadUserByUsername() 으로 db 조회
        // 내부흐름
        //AuthService
        //    ↓
        //AuthenticationManager
        //    ↓
        //DaoAuthenticationProvider
        //    ↓
        //CustomUserDetailsService
        //    ↓
        //UserRepository
        //    ↓
        //PasswordEncoder.matches()

        // 인증 성공 후 사용자 조회
        UserEntity user = userRepository.findById(request.userid())
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "로그인 정보가 올바르지 않습니다"));

        // 로그인 인증이 성공하면 issueTokens()를 호출해서 Access Token과 Refresh Token을 발급
        return issueTokens(user);
    }

    // Refresh Token으로 재발급
    // Refresh Token 재발급 흐름
    // [브라우저]
    // Access Token 만료로 API 요청 실패
    // 401 Unauthorized
    //        ↓
    // [브라우저]
    // POST /api/auth/refresh
    // Refresh Token 전달
    //        ↓
    // [AuthService.refresh()]
    //        ↓
    // [RefreshTokenService.verifyAndGetUser()]
    //        ↓
    // Refresh Token DB 검증
    //        ↓
    // [RefreshTokenService.revoke()]
    //        ↓
    // 기존 Refresh Token 폐기
    //        ↓
    // [issueTokens()]
    //        ↓
    // 새 Access Token + 새 Refresh Token 발급
    public AuthResponse refresh(TokenRefreshRequest request) {
        // Refresh Token 검증
        UserEntity user = refreshTokenService.verifyAndGetUser(request.refreshToken());
        //기존 Refresh Token 폐기
        refreshTokenService.revoke(request.refreshToken());
        // 새 토큰 발급
        // {
        //  "tokenType": "Bearer",
        //  "accessToken": "새 Access Token",
        //  "refreshToken": "새 Refresh Token",
        //  "expiresIn": 1800,
        //  "user": {
        //    "userid": "user1",
        //    "username": "일반사용자",
        //    "role": "USER"
        //  }
        //}
        return issueTokens(user);
    }

    // 로그아웃 처리
    //1. 서버에서 Refresh Token 폐기
    //2. 브라우저에서 Access Token 삭제
    //3. 브라우저에서 Refresh Token 삭제
    // Access Token
    // → 서버 DB에 저장하지 않음
    // → 클라이언트가 삭제해야 함
    // Refresh Token
    // → 서버 DB에 저장함
    // → 서버에서 revoke 가능
    public void logout(TokenRefreshRequest request) {
        refreshTokenService.revoke(request.refreshToken());
    }

    // 토큰 발급 공통 메서드
    private AuthResponse issueTokens(UserEntity user) {
        // Access Token 보호 API를 호출할 때 사용
        //  Authorization: Bearer AccessToken값
        //{
        //  "sub": "user1",
        //  "roles": ["ROLE_USER"],
        //  "iss": "rest-api-user",
        //  "iat": 1710000000,
        //  "exp": 1710001800
        //}
        String accessToken = jwtService.createAccessToken(user);

        // Refresh Token을 DB에 저장합니다.
        // 보안상 보통 Refresh Token 원문을 그대로 저장하지 않고, 해시값을 저장
        // Refresh Token 원문
        // → 브라우저에게 응답
        // Refresh Token 해시값
        // → DB 저장
        String refreshToken = refreshTokenService.createRefreshToken(user);

        // 응답 객체 생성
        // {
        //  "tokenType": "Bearer",
        //  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
        //  "refreshToken": "랜덤문자열...",
        //  "expiresIn": 1800,
        //  "user": {
        //    "userid": "user1",
        //    "username": "일반사용자",
        //    "email": "user1@test.com",
        //    "role": "USER"
        //  }
        //}
        return AuthResponse.bearer(
                accessToken,
                refreshToken,
                jwtService.getAccessTokenExpiresInSeconds(),
                UserResponse.from(user)
        );
    }
}
