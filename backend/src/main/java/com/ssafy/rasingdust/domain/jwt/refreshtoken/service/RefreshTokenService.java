package com.ssafy.rasingdust.domain.jwt.refreshtoken.service;

import com.ssafy.rasingdust.domain.jwt.refreshtoken.repository.RefreshTokenRepository;
import com.ssafy.rasingdust.domain.jwt.refreshtoken.entity.RefreshToken;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken findByRefreshToken(String refreshToken) {
        return refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("no refreshToken with your request refreshToken"));
    }
}
