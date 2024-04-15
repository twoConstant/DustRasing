package com.ssafy.rasingdust.global.config.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;
    private final static String HEADER_AUTHORIZATION = "Authorization";
    private final static String TOKEN_PREFIX = "Bearer";


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
//        System.out.println("come in jwt filter");

        // 인증 API가 아닌경우 인증 로직을 거치지 않음
        if (request.getRequestURI().startsWith("/api/problem")
            || request.getRequestURI().startsWith("/api/token")
            || request.getRequestURI().startsWith("/api/swagger-ui.html")
        ) {
            filterChain.doFilter(request, response);
            return;
        }

        // request에서 토큰 추출 ex) Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        String authorizationHeader = request.getHeader(HEADER_AUTHORIZATION);    // "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        String token = getAccessToken(authorizationHeader);

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formattedTime = now.format(formatter);
        log.info("API 호출 시각 : {}", formattedTime);
        log.info("토큰 : {}", token);
        // 토큰 유효성 검사
        if (tokenProvider.isValidAccessToken(token)) {
            Long userId = tokenProvider.getUserId(token);
            log.info("API 호출 유저 : {}", userId);
            // 인증서 발급
            Authentication authentication = tokenProvider.getAuthentication(token);
            // spring security에 인증객체 등록
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
//        System.out.println("come out jwt filter");
        // 해당 요청을 다음 필터 절차로 넘김
        filterChain.doFilter(request, response);
    }

    private String getAccessToken(String authorizationHeader) {
        // jwt 토큰 해더가 있다면 토큰 반환
        if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
            return authorizationHeader.substring(TOKEN_PREFIX.length());
        }
        // 없으면 null
        return null;
    }

}
