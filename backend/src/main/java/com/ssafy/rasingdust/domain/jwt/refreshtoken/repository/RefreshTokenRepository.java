package com.ssafy.rasingdust.domain.jwt.refreshtoken.repository;

import com.ssafy.rasingdust.domain.jwt.refreshtoken.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByUserId(Long userId);
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
    boolean existsByUserId(Long userId);
}
