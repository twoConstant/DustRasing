package com.ssafy.rasingdust.domain.user.controller;

import com.ssafy.rasingdust.domain.user.dto.response.FeedCharacterResponse;
import com.ssafy.rasingdust.domain.user.dto.response.GetUserResponse;
import com.ssafy.rasingdust.domain.user.dto.response.SliceResponse;
import com.ssafy.rasingdust.domain.user.dto.response.VisitUserResponse;
import com.ssafy.rasingdust.domain.user.service.UserService;
import com.ssafy.rasingdust.global.result.ResultCode;
import com.ssafy.rasingdust.global.result.ResultResponse;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
@Slf4j
public class UserController implements UserControllerDocs {

    private final UserService userService;


    @GetMapping()
    public ResponseEntity<ResultResponse> getUser(
        @AuthenticationPrincipal UserDetails userDetails) {
        GetUserResponse response = userService.getUser(Long.valueOf(userDetails.getUsername()));
        return ResponseEntity.ok(new ResultResponse(ResultCode.GET_USER_SUCCESS, response));
    }

    @PostMapping("/follow/{fromId}")
    public ResponseEntity<ResultResponse> followUser(
        @AuthenticationPrincipal UserDetails userDetails, @PathVariable Long fromId) {
        userService.followUser(Long.valueOf(userDetails.getUsername()), fromId);
        return ResponseEntity.ok(new ResultResponse(ResultCode.CREATE_FOLLOW_SUCCESS));
    }

    @DeleteMapping("/unfollow/{fromId}")
    public ResponseEntity<ResultResponse> unfollowUser(
        @AuthenticationPrincipal UserDetails userDetails, @PathVariable Long fromId) {
        userService.unFollowUser(Long.valueOf(userDetails.getUsername()), fromId);
        return ResponseEntity.ok(new ResultResponse(ResultCode.DELETE_UNFOLLOW_SUCCESS));
    }

    @GetMapping("/following/list/{userId}")
    public ResponseEntity<ResultResponse> getFollowingList(
        @AuthenticationPrincipal UserDetails userDetails, @PathVariable Long userId,
        Pageable pageable) {
        SliceResponse result = userService.getFollowingList(Long.valueOf(userDetails.getUsername()),
            userId, pageable);
        return ResponseEntity.ok(new ResultResponse(ResultCode.GET_FOLLOWINGLIST_SUCCESS, result));
    }

    @GetMapping("/follower/list/{userId}")
    public ResponseEntity<ResultResponse> getFollowerList(
        @AuthenticationPrincipal UserDetails userDetails, @PathVariable Long userId,
        Pageable pageable) {
        SliceResponse result = userService.getFollowerList(Long.valueOf(userDetails.getUsername()),
            userId, pageable);
        return ResponseEntity.ok(new ResultResponse(ResultCode.GET_FOLLOWERLIST_SUCCESS, result));
    }

    @PutMapping("/character")
    public ResponseEntity<FeedCharacterResponse> feedCharacter(
        @AuthenticationPrincipal UserDetails userDetails) {
        FeedCharacterResponse feedCharacterResponse = userService.feedCharacter(
            Long.valueOf(userDetails.getUsername()));
        return ResponseEntity.ok(feedCharacterResponse);
    }


    @GetMapping("/search")
    public ResponseEntity<ResultResponse> getUserList(
        @AuthenticationPrincipal UserDetails userDetails, @RequestParam String userName,
        @PageableDefault(sort = "id", direction = Sort.Direction.DESC) Pageable pageable) {
        SliceResponse response = userService.findByuserNameStartsWith(
            Long.valueOf(userDetails.getUsername()), userName, pageable);
        return ResponseEntity.ok(new ResultResponse(ResultCode.GET_USERLIST_SUCCESS, response));
    }

    @GetMapping("/invitor/{userId}")
    public ResponseEntity<ResultResponse> visitUser(
        @AuthenticationPrincipal UserDetails userDetails,
        @PathVariable Long userId) {
        VisitUserResponse response = userService.visitUser(Long.valueOf(userDetails.getUsername()),
            userId);
        return ResponseEntity.ok(new ResultResponse(ResultCode.GET_VISITUSER_SUCCESS, response));
    }

    @GetMapping("/rank")
    public ResponseEntity<ResultResponse> getUserRank(
        @AuthenticationPrincipal UserDetails userDetails) {
        int response = userService.getUserRank(Long.valueOf(userDetails.getUsername()));
        return ResponseEntity.ok(new ResultResponse(ResultCode.GET_USER_RANK_SUCCESS, response));
    }

    @Operation(summary = "콕 찌르기")
    @PostMapping("/kock/{userId}")
    public ResponseEntity<Void> sendKock(@AuthenticationPrincipal UserDetails user,
        @PathVariable Long userId) {
        userService.sendKock(Long.valueOf(user.getUsername()), userId);
        return ResponseEntity.ok().build();
    }
}
