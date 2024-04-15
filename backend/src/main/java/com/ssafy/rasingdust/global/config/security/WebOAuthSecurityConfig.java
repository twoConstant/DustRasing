package com.ssafy.rasingdust.global.config.security;

import com.ssafy.rasingdust.domain.jwt.refreshtoken.repository.RefreshTokenRepository;
import com.ssafy.rasingdust.domain.user.service.UserServiceImpl;
import com.ssafy.rasingdust.global.config.security.jwt.TokenAuthenticationFilter;
import com.ssafy.rasingdust.global.config.security.jwt.TokenProvider;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


@RequiredArgsConstructor
@Configuration
@Slf4j
public class WebOAuthSecurityConfig {

    private final OAuth2UserCustomService oAuth2UserCustomService;    // 로드 유저로 User 엔티티 상태 관리
    private final TokenProvider tokenProvider;    // 토큰 생성 및 검증 역할
    private final RefreshTokenRepository refreshTokenRepository;    // 토큰 정보 저장고
    private final UserServiceImpl userServiceImpl;    // 유저 엔티티

    @Bean
    public WebSecurityCustomizer configure() {    // 스프링 시큐리티 기능 비활성화
        return (web) -> web.ignoring()
            .requestMatchers("/img/**", "/css/**", "/js/**");
    }

    @Bean    // 시큐리티 인증 시스템
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//         토큰 방식으로 하기 때문에 기존의 사용하던 폼로그인, 세션 비활
        log.info("into Chain");
        return http
            // jwt 토큰 기반으로 csrf 비활성화
            .csrf(AbstractHttpConfigurer::disable)
            // 모든 접근 허용
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            // 토큰 인증 기반이라 세션기반 비활성화
            .sessionManagement((sessionManagement) ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // jwt 토큰 인증 필터 추가
            .addFilterBefore(tokenAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter.class)
            // 요청 url 제한(모든 요청 허용)
            .authorizeRequests(authorizeRequests ->
                authorizeRequests.requestMatchers("/user/**").authenticated()
                .anyRequest().permitAll())

//                authorizeRequests.anyRequest().permitAll())
            //                .requestMatchers("/api/token").permitAll()
            //                .requestMatchers("/api/**").permitAll()
            //                .requestMatchers("/api/**").authenticated()

            // oauth2Login 프로세스 핵심 로직
            .oauth2Login(oauth2Login ->
                oauth2Login
                    // 리소스 서버 자원 리다이렉트 받을 url(지금은 서버사이드지만 추후엔 프론트로 옮겨야됨)
                    .loginPage("/login")
                    // 인증 요청 정보 중간 보관 단계
                    .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.authorizationRequestRepository(
                            oAuth2AuthorizationRequestBasedOnCookieRepository()))
                    // 카카오 인증 완료, 토근 생성 및 추가 사용자 정보 처리
                    .successHandler(oAuth2SuccessHandler())
                    // 유저 정보 업데이트 및 유저엔티티 테이블 추가
                    .userInfoEndpoint(userInfoEndpoint ->
                        userInfoEndpoint.userService(oAuth2UserCustomService)))
            // 로그아웃 성공시 리다이렉트 url
            .logout(logout ->
                logout.logoutSuccessUrl("/login"))
            // 인증 되지 않은 url 요청시 처리 프로세스
            .exceptionHandling(exceptionHandling ->
                exceptionHandling.defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    new AntPathRequestMatcher("/api/**")))
            .build();
    }


    // cors 설정, Credential true 시 Origin url(client url)
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173", "http://localhost:5174", "https://j10d103.p.ssafy.io")); // 모든 출처 허용
        configuration.setAllowedMethods(
            Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")); // 허용할 HTTP 메소드 지정
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "accept", "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers")); // 모든 헤더 허용
        configuration.setAllowCredentials(true); // 크레덴셜 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 모든 경로에 대해 위 설정 적용
        return source;
    }

    @Bean
    public OAuth2SuccessHandler oAuth2SuccessHandler() {    // 인증 성공시 처리 로직
        return new OAuth2SuccessHandler(tokenProvider,
            refreshTokenRepository,
            oAuth2AuthorizationRequestBasedOnCookieRepository(),
            userServiceImpl
        );
    }

    @Bean    // 요청 헤더에 있는 토큰의 유효성을 검증하는 인증 절차
    public TokenAuthenticationFilter tokenAuthenticationFilter() {    //
        log.info("인증 절차 수행");
        return new TokenAuthenticationFilter(tokenProvider);
    }

    @Bean    // 인증 요청과 관련된 상태를(로그인, 인가, 토큰, 정보 받아오기...) 저장할 저장소
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    @Bean    // 스프링 시큐리티의 비밀번호 해싱 해주는 역학
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
