package com.ssafy.rasingdust.domain.user.controller;

import com.ssafy.rasingdust.domain.user.dto.response.FeedCharacterResponse;
import com.ssafy.rasingdust.domain.user.dto.response.GetUserResponse;
import com.ssafy.rasingdust.domain.user.dto.response.SliceResponse;
import com.ssafy.rasingdust.domain.user.dto.response.VisitUserResponse;
import com.ssafy.rasingdust.global.result.ResultResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Tag(name ="유저 관련 Controller", description = "유저 및 팔로우 API")
public interface UserControllerDocs {

    @Operation(summary = "팔로우 요청", description = "PathVariable 받은 user_id에 해당하는 유저를 팔로우")
    @ApiResponse(responseCode = "201", description = "해당 유저 팔로우를 성공하였습니다.")
    @PostMapping("/follow/{fromId}")
    public ResponseEntity<ResultResponse> followUser(
        @AuthenticationPrincipal UserDetails userDetails, @PathVariable Long fromId);


    @Operation(summary = "언팔로우 요청", description = "PathVariable 받은 user_id에 해당하는 유저를 언팔로우")
    @ApiResponse(responseCode = "201", description = "해당 유저 언팔로우를 성공하였습니다.")
    @DeleteMapping("/unfollow/{fromId}")
    public ResponseEntity<ResultResponse> unfollowUser(
        @AuthenticationPrincipal UserDetails userDetails, @PathVariable Long fromId);


    @Operation(summary = "팔로잉 리스트 조회", description = "PathVariable 받은 user_id에 해당하는 유저의 팔로잉 리스트를 조회")
    @ApiResponse(responseCode = "200", description = "유저의 팔로잉 리스트 조회에 성공하였습니다.", content = @Content(schema = @Schema(implementation = SliceResponse.class)))
    @GetMapping("/following/list/{userId}")
    public ResponseEntity<ResultResponse> getFollowingList (
        @AuthenticationPrincipal UserDetails userDetails, @PathVariable Long userId, Pageable pageable);


    @Operation(summary = "팔로워 리스트 조회", description = "PathVariable 받은 user_id에 해당하는 유저의 팔로워 리스트를 조회")
    @ApiResponse(responseCode = "200", description = "유저의 팔로워 리스트 조회에 성공하였습니다.", content = @Content(schema = @Schema(implementation = SliceResponse.class)))
    @GetMapping("/follower/list/{userId}")
    public ResponseEntity<ResultResponse> getFollowerList(
        @AuthenticationPrincipal UserDetails userDetails, @PathVariable Long userId, Pageable pageable);

    @Operation(summary = "유저 검색", description = "요청받은 문자열에 해당하는 유저의 리스트 정보 및 해당 유저를 같이 팔로우하는 수와 대표 닉네임를 조회")
    @ApiResponse(responseCode = "200", description = "유저리스트 검색에 성공하였습니다.", content = @Content(schema = @Schema(implementation = SliceResponse.class)))
    @GetMapping("/search")
    public ResponseEntity<ResultResponse> getUserList(@AuthenticationPrincipal UserDetails userDetails, @RequestParam String userName, Pageable pageable);

    @Operation(summary = "유저 조회", description = "현재 로그인 상태의 유저 전체 정보 반환")
    @ApiResponse(responseCode = "200", description = "해당 유저 조회에 성공하였습니다.", content = @Content(schema = @Schema(implementation = GetUserResponse.class)))
    @GetMapping()
    public ResponseEntity<ResultResponse> getUser(@AuthenticationPrincipal UserDetails userDetails);

    @Operation(summary = "물 주기", description = "보유한 물의 개수가 1이상일 경우 growthPoint++, bottle--")
    @ApiResponse(responseCode = "200", description = "해당 유저의 펫 먹이 주기를 성공하였습니다.", content = @Content(schema = @Schema(implementation = FeedCharacterResponse.class)))
    @PutMapping("/character")
    public ResponseEntity<FeedCharacterResponse> feedCharacter(@AuthenticationPrincipal UserDetails userDetails);

    @Operation(summary = "다른 유저 페이지 방문", description = "PathVariable 받은 user_id에 해당하는 유저의 정보를 반환합니다.")
    @ApiResponse(responseCode = "200", description = "해당 유저 페이지 방문에 성공하였습니다.", content = @Content(schema = @Schema(implementation = VisitUserResponse.class)))
    @GetMapping("/invitor/{userId}")
    public ResponseEntity<ResultResponse> visitUser(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long userId);

    @Operation(summary = "유저 랭킹 조회", description = "현재 로그인된 유저의 랭킹을 조회합니다.")
    @ApiResponse(responseCode = "200", description = "해당 유저 랭킹 조회에 성공하였습니다.", content = @Content(schema = @Schema(implementation = Integer.class)))
    @GetMapping("/rank")
    public ResponseEntity<ResultResponse> getUserRank(@AuthenticationPrincipal UserDetails userDetails);

}
