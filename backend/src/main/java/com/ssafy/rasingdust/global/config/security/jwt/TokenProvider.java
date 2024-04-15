package com.ssafy.rasingdust.global.config.security.jwt;

import com.ssafy.rasingdust.domain.user.entity.User;
import com.ssafy.rasingdust.global.exception.BusinessLogicException;
import com.ssafy.rasingdust.global.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.HashSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

@RequiredArgsConstructor
@Service
@Slf4j
public class TokenProvider {

    private final JwtProperties jwtProperties;

    public String generateAccessToken(User user, Duration expiredAt) {    // 시간 주입
        Date now = new Date();
        return makeAccessToken(new Date(now.getTime() + expiredAt.toMillis()), user);
    }

    public String generateRefreshToken(User user, Duration expiredAt) {    // 시간 주입
        Date now = new Date();
        return makeRefreshToken(new Date(now.getTime() + expiredAt.toMillis()), user);
    }

    // JWT 토큰 생성 메서드
    private String makeAccessToken(Date expiry, User user) {
        Date now = new Date();

        return Jwts.builder()
                // 헤더
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)  // 헤더 세팅
                // 내용
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(now)
                .setExpiration(expiry)
//                .setSubject(user.getEmail())
                .setSubject(String.valueOf(user.getId()))
                .claim("id", user.getId())
                // 클래임 추가 가능
//                .claim("name", user.getName())  // 사용자 이름
//                .claim("role", user.getRole())  // 사용자 역할
                // 서명
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretAccesskey().getBytes(StandardCharsets.UTF_8))
                .compact();
    }

    private String makeRefreshToken(Date expiry, User user) {
        Date now = new Date();

        return Jwts.builder()
            // 헤더
            .setHeaderParam(Header.TYPE, Header.JWT_TYPE)  // 헤더 세팅
            // 내용
            .setIssuer(jwtProperties.getIssuer())
            .setIssuedAt(now)
            .setExpiration(expiry)
//                .setSubject(user.getEmail())
            .setSubject(String.valueOf(user.getId()))
            .claim("id", user.getId())
            // 클래임 추가 가능
//                .claim("name", user.getName())  // 사용자 이름
//                .claim("role", user.getRole())  // 사용자 역할
            // 서명
            .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretRefreshkey().getBytes(StandardCharsets.UTF_8))
            .compact();
    }

    // JWT 토큰 유효성 검사
    public boolean isValidAccessToken(String token) {
        try {
            // 기본적인 JWT 복호화 과정
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretAccesskey().getBytes(StandardCharsets.UTF_8)) // 복호화
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            throw new BusinessLogicException(ErrorCode.ACCESSTOKEN_DURATION_EXPIRED);
//            return false;
        } catch (Exception e) {
            throw new BusinessLogicException(ErrorCode.INVAILED_ACCESSTOEKN);
//            return false;
        }
    }

    public boolean isValidRefreshToken(String token) {
        try {
            log.info("리프래시 토큰 유효성 검사 수행");
            // 기본적인 JWT 복호화 과정
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretRefreshkey().getBytes(StandardCharsets.UTF_8)) // 복호화
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            throw new BusinessLogicException(ErrorCode.REFRESHTOKEN_DURATION_EXPIRED);
        } catch (Exception e) {
            throw new BusinessLogicException(ErrorCode.INVAILED_REFRESHTOKEN);
        }
    }




    // 트콘 기반 인증 정보 가져오는 메서드, spring security 클래스
    public Authentication getAuthentication(String token) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        // 권한 추가 등록 가능
//        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        org.springframework.security.core.userdetails.User user = new org.springframework.security.core.userdetails.User(
            getAccessTokenClaims(token).getSubject(), " ", authorities);

        Authentication authentication = new UsernamePasswordAuthenticationToken(user, token, authorities);
        return authentication;
    }

    // 토큰 기반 유저 ID를 가져오는 메서드 Claim은 JWT의 핵심 정보가 있는 Body이다.
    public Long getUserId(String token) {
        return getAccessTokenClaims(token)
                .get("id", Long.class);
    }

    // Claims을 추출하는 메서드
    private Claims getAccessTokenClaims(String token) {
        return Jwts.parser()
                .setSigningKey(jwtProperties.getSecretAccesskey().getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }

}
