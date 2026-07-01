package com.example.restapiuser.config;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // csrf 꺼라
                .csrf(AbstractHttpConfigurer::disable)
                    // abstractHttpConfigurer.disable()
                // 세션 꺼라
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 경로에 대한 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/", "/index.html",
                                "/promise2.html", "/promisetest.html",
                                "/css/**", "/js/**", "/img/**", "/favicon.ico"
                        ).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // 회원가입과 로그인/재발급은 토큰 없이 접근 가능
                        .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                        .requestMatchers(HttpMethod.POST,
                                "/api/auth/login",
                                "/api/auth/refresh",
                                "/api/auth/logout"
                        ).permitAll()
                        // 나머지 API는 Authorization: Bearer <accessToken> 필요
                        .anyRequest().authenticated()
                )
                //이 서버는 OAuth2 Resource Server 방식으로 동작한다.
                //요청의 Authorization 헤더에서 Bearer Token을 읽어라.
                //그 토큰을 JWT로 해석하고 검증해라.
                //브라우저 요청이 이렇게 들어오면:
                    // GET /api/users
                    // Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
                // Spring Security가 자동으로 다음 일을 합니다.
                //1. Authorization 헤더 확인
                //2. Bearer 토큰 추출
                //3. JWT 서명 검증
                //4. 만료 시간 exp 확인
                //5. JWT 안의 sub, roles claim 읽기
                //6. Authentication 객체 생성
                //7. Controller로 요청 전달
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 로그인할 때 사용하는 인증 관리자입니다.
    // AuthService
        //→ AuthenticationManager
        //→ DaoAuthenticationProvider
        //→ CustomUserDetailsService
        //→ UserRepository
        //→ PasswordEncoder.matches()
        //→ 인증 성공 또는 실패
        // 로그인 성공 후에야 JwtService가 Access Token을 발급
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }


    // JWT Access Token을 생성할 때 사용합니다. (로그인 성공 시 JwtService에서 사용)
    // 회원 로그인 성공
    // → JwtEncoder가 JWT 생성
    // → Access Token 응답
    @Bean
    public JwtEncoder jwtEncoder(JwtProperties jwtProperties) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(secretKey(jwtProperties)));
    }


    // JWT Access Token을 검증할 때 사용합니다. 요청이 들어올 때 Spring Security가 이 Decoder를 사용

    //검증하는 내용은 다음입니다.
        // JWT 서명이 올바른가?
        // 만료 시간이 지나지 않았는가?
        // 토큰 구조가 정상인가?

    // 현재 예제는 HS256 방식입니다.
    //  HS256 = 하나의 secret key로 서명도 하고 검증도 하는 방식
    //  즉, 서버가 가지고 있는 secret 값이 매우 중요합니다.
    @Bean
    public JwtDecoder jwtDecoder(JwtProperties jwtProperties) {
        return NimbusJwtDecoder
                .withSecretKey(secretKey(jwtProperties))
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }


    // JWT 안의 권한 정보를 Spring Security 권한으로 바꿔주는 설정
    //  JWT 안의 roles claim을 권한 목록으로 사용하라
      // 기본적으로 Spring Security는 JWT 권한 앞에 SCOPE_  이므로  .setAuthorityPrefix("");
    //  JWT roles: ["ROLE_ADMIN"]  → Spring Security 권한: ROLE_ADMIN
    //  만약 prefix를 비우지 않으면 의도와 다른 권한명이 될 수 있습니다.
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("");   // JWT 권한 앞에 있는 SCOPE_ 를 제거한다
        authoritiesConverter.setAuthoritiesClaimName("roles");

        JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
        authenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return authenticationConverter;
    }


    // application.yml에 있는 secret 문자열을 바이트 배열로 바꾼 뒤, HMAC SHA-256용 SecretKey로 만듭니다.
    // 이 SecretKey는 두 곳에서 사용됩니다.
     // JwtEncoder → JWT 생성
     // JwtDecoder → JWT 검증
    private SecretKey secretKey(JwtProperties jwtProperties) {
        byte[] secretBytes = jwtProperties.secret().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return new SecretKeySpec(secretBytes, "HmacSHA256");
    }

    // 이 설정 파일의 전체 실행 흐름
    // 로그인할 때
    // [브라우저]
    // POST /api/auth/login
    // userid, password
    //        ↓
    // [SecurityConfig]
    // /api/auth/** permitAll 이므로 통과
    //        ↓
    // [AuthRestController]
    //        ↓
    // [AuthService]
    //        ↓
    // [AuthenticationManager]
    //        ↓
    // [CustomUserDetailsService]
    //        ↓
    // [UserRepository]
    //        ↓
    // [PasswordEncoder]
    //        ↓
    // [JwtService]
    //        ↓
    // [JwtEncoder]
    //        ↓
    // ccess Token + Refresh Token 응답
    // 보호 API를 호출할 때
    // [브라우저]
    // GET /api/users
    // Authorization: Bearer AccessToken
    //        ↓
    // [SecurityConfig]
    // .anyRequest().authenticated()
    //        ↓
    // [OAuth2 Resource Server]
    //        ↓
    // [JwtDecoder]
    //        ↓
    // [JwtAuthenticationConverter]
    //        ↓
    // Authentication 생성
    //        ↓
    // [UserRestController]
    //        ↓
    // [UserService]
    //        ↓
    // 권한별 CRUD 검사
}
