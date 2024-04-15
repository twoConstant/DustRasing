package com.ssafy.rasingdust.domain.jwt.token.controller;

import com.ssafy.rasingdust.domain.jwt.refreshtoken.dto.request.CreateAccessTokenRequest;
import com.ssafy.rasingdust.domain.jwt.refreshtoken.entity.RefreshToken;
import com.ssafy.rasingdust.domain.jwt.token.dto.response.CreateAccessTokenResponse;
import com.ssafy.rasingdust.domain.jwt.token.service.TokenService;
import com.ssafy.rasingdust.global.result.ResultCode;
import com.ssafy.rasingdust.global.result.ResultResponse;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class TokenController implements TokenControllerDocs{
    private final TokenService tokenService;

    @PostMapping("/token")
    public ResponseEntity<ResultResponse> createNewAccessToken(@RequestBody CreateAccessTokenRequest request) {
        log.info("activate token Controller");
        String response = tokenService.createNewAccessToken(request.getRefreshToken());
        log.info("deactivate token Controller");
        return ResponseEntity.ok(new ResultResponse(ResultCode.CREATE_ACCESSTOKEN_SUCCESS, response));
    }

    @PostMapping("/token/develop/{userId}")
    public ResponseEntity<ResultResponse> createDevelopToken(@PathVariable Long userId){
        RefreshToken response = tokenService.createDevelopToken(userId);
        return ResponseEntity.ok(new ResultResponse(ResultCode.POST_DEVELOP_TOKEN_SUCCESS, response));
    }
}
