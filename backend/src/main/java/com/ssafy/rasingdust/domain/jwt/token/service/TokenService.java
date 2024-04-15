package com.ssafy.rasingdust.domain.jwt.token.service;

import com.ssafy.rasingdust.domain.jwt.refreshtoken.entity.RefreshToken;
import com.ssafy.rasingdust.domain.jwt.refreshtoken.repository.RefreshTokenRepository;
import com.ssafy.rasingdust.domain.jwt.refreshtoken.service.RefreshTokenService;
import com.ssafy.rasingdust.domain.user.entity.User;
import com.ssafy.rasingdust.domain.user.service.UserServiceImpl;
import com.ssafy.rasingdust.global.config.security.jwt.TokenProvider;
import com.ssafy.rasingdust.global.exception.BusinessLogicException;
import com.ssafy.rasingdust.global.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final UserServiceImpl userServiceImpl;
    private final RefreshTokenService refreshTokenService;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    // 요청의 리프레시 토큰을 확인하고 2시간짜리 새로운 토큰을 발행하는 메서드
    public String createNewAccessToken(String refreshToken) {
        // 리프레시 토큰의 유효성 검사
        if(!tokenProvider.isValidRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("your token is not available");
        }

        // 새로운 엑세스 토큰 생성해 반환
        Long userId = refreshTokenService.findByRefreshToken(refreshToken).getUserId();
        User user = userServiceImpl.findById(userId);
        return tokenProvider.generateAccessToken(user, Duration.ofHours(2));
    }

    public RefreshToken createDevelopToken(Long userId) {
        // 만약 해당 유저의 refresh토큰이 있다면 이미 있습니다. => 충돌 에러
        if(refreshTokenRepository.existsByUserId(userId)) {
            throw new BusinessLogicException(ErrorCode.USER_DEVELOP_TOKEN_CONFLICT);
        }

        // 없으면 30일 짜리 개발용 토큰 생성
        User user = userServiceImpl.findById(userId);

        String refreshToken = tokenProvider.generateRefreshToken(user, Duration.ofDays(30));
        RefreshToken savedRefreshToken = RefreshToken.builder()
            .userId(user.getId())
            .refreshToken(refreshToken)
            .build();
        refreshTokenRepository.save(savedRefreshToken);
        return savedRefreshToken;
    }


}
