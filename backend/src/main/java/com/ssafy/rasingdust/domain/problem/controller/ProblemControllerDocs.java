package com.ssafy.rasingdust.domain.problem.controller;

import com.ssafy.rasingdust.domain.problem.dto.response.AddBottleResponse;
import com.ssafy.rasingdust.domain.problem.dto.response.GetProblemResponse;
import com.ssafy.rasingdust.global.result.ResultResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Tag(name ="문제 관련 Controller", description = "문제 관련 API")
public interface ProblemControllerDocs {

    @Operation(summary = "랜덤 문제 조회", description = "QueryString으로 number를 받아 해당 쓰래기 분류 String과 2개의 Random 쓰래기 분류 String 반환")
    @ApiResponse(responseCode = "200", description = "해당 문제 조회에 성공하였습니다.", content = @Content(schema = @Schema(implementation = GetProblemResponse.class)))
    @GetMapping()
    public ResponseEntity<ResultResponse> getProblem(@RequestParam(name = "number") Long number);

    @Operation(summary = "정답 처리 요청", description = "현재 유저의 bottle++, solvedCnt++")
    @ApiResponse(responseCode = "200", description = "해당 유저의 보유 물병 + 1, 풀이 수 + 1을 성공하였습니다.", content = @Content(schema = @Schema(implementation = AddBottleResponse.class)))
    @PutMapping()
    public ResponseEntity<ResultResponse> addBottle(@AuthenticationPrincipal UserDetails userDetails);
}
