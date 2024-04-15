package com.ssafy.rasingdust.domain.jwt.token.controller;

import com.ssafy.rasingdust.domain.jwt.refreshtoken.dto.request.CreateAccessTokenRequest;
import com.ssafy.rasingdust.domain.jwt.token.dto.response.CreateAccessTokenResponse;
import com.ssafy.rasingdust.global.result.ResultResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@Tag(name ="Token 관련 Controller", description = "AccessToken 생성 API")
public interface TokenControllerDocs {
    @Operation(summary = "AccessToken 생성 요청", description = "기존 AccessToken 만료된 경우 RequestBody로 RefreshToken을 받아 AccessToken 생성")
    @ApiResponse(responseCode = "201", description = "AccessToken 발급에 성공하였습니다.")
    @PostMapping("/token")
    public ResponseEntity<ResultResponse> createNewAccessToken(@RequestBody CreateAccessTokenRequest request);

    @Operation(summary = "Develop Token 생성 요청", description = "PathVariable 받은 user_id에 해당하는 개발용 Token 생성후 반환")
    @ApiResponse(responseCode = "201", description = "개발용 토큰 발급에 성공하였습니다.")
    @PostMapping("/token/develop/{userId}")
    public ResponseEntity<ResultResponse> createDevelopToken(@PathVariable Long userId);

}
