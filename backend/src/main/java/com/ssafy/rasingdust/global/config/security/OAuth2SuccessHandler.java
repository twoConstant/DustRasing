package com.ssafy.rasingdust.global.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssafy.rasingdust.domain.jwt.refreshtoken.entity.RefreshToken;
import com.ssafy.rasingdust.domain.jwt.refreshtoken.repository.RefreshTokenRepository;
import com.ssafy.rasingdust.domain.user.entity.User;
import com.ssafy.rasingdust.domain.user.service.UserServiceImpl;
import com.ssafy.rasingdust.global.config.security.cookie.CookieUtil;
import com.ssafy.rasingdust.global.config.security.jwt.TokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@RequiredArgsConstructor
@Component
@Slf4j
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    public static final Duration REFRESH_TOKEN_DURATION = Duration.ofDays(14);
    public static final Duration ACCESS_TOKEN_DURATION = Duration.ofDays(1);
    public static final String REDIRECT_PATH = "https://j10d103.p.ssafy.io/";

    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository;
    private final UserServiceImpl userServiceImpl;

    // 사용자가 정상 로그인 완료시 자동으로 호출되는 메서드
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException {
        log.info("into SuccessHandler");

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
        String name = (String) properties.get("nickname");
        User user = userServiceImpl.findByUserName(name);

        // 인증이 완료된 이휴 인증관련 속성 정리해주기
        clearAuthenticationAttributes(request, response);

        String refreshToken = tokenProvider.generateRefreshToken(user, REFRESH_TOKEN_DURATION);
        String accessToken = tokenProvider.generateAccessToken(user, ACCESS_TOKEN_DURATION);
        saveRefreshToken(user.getId(), refreshToken);
        // refresh token은 쿠키로
        addRefreshTokenToCookie(request, response, refreshToken);

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        // accessToken은 body로 전달
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);

        // ObjectMapper를 사용하여 Map을 JSON으로 변환
        new ObjectMapper().writeValue(response.getWriter(), tokens);
        log.info("deactivate SuccessHandler");
    }

    private void saveRefreshToken(Long userId, String newRefreshToken) {
        RefreshToken refreshToken = refreshTokenRepository.findByUserId(userId)
            .map(entity -> entity.update(newRefreshToken))
            .orElse(new RefreshToken(userId, newRefreshToken));

        refreshTokenRepository.save(refreshToken);
    }

    private void addRefreshTokenToCookie(HttpServletRequest request, HttpServletResponse response,
        String refreshToken) {
        int cookieMaxAge = (int) REFRESH_TOKEN_DURATION.toSeconds();

        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN_COOKIE_NAME);
        CookieUtil.addCookie(response, REFRESH_TOKEN_COOKIE_NAME, refreshToken, cookieMaxAge);
    }

    private void clearAuthenticationAttributes(HttpServletRequest request,
        HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        oAuth2AuthorizationRequestBasedOnCookieRepository.removeAuthorizationRequestCookies(request,
            response);
    }

    private String getTargetUrl(String token) {
        return UriComponentsBuilder.fromUriString(REDIRECT_PATH)
            .queryParam("token", token)
            .build()
            .toUriString();
    }
}
