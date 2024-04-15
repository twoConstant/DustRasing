package com.ssafy.rasingdust.domain.notification.controller;


import com.ssafy.rasingdust.domain.notification.dto.SseDto;
import com.ssafy.rasingdust.domain.notification.service.NotificationService;
import com.ssafy.rasingdust.domain.user.dto.response.SliceResponse;
import com.ssafy.rasingdust.global.result.ResultCode;
import com.ssafy.rasingdust.global.result.ResultResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/notices")
@RequiredArgsConstructor
@Tag(name = "NotificationController", description = "알림함 관련 API")
public class NotificationController {

    private final NotificationService notificationService;

    @Operation(summary = "알림함 조회")
    @GetMapping()
    public ResponseEntity<ResultResponse> getNoticeList(
        @AuthenticationPrincipal UserDetails loginUser, Pageable pageable) {
        SliceResponse<SseDto> sliceResponse = notificationService.getNoticeList(loginUser,
            pageable);
        return ResponseEntity.ok(
            new ResultResponse(ResultCode.GET_NOTIFICATION_SUCCESS, sliceResponse));
    }

    @Operation(summary = "알림 읽음처리")
    @PutMapping("/{id}")
    public ResponseEntity<ResultResponse> readNotice(@AuthenticationPrincipal UserDetails loginUser,
        @PathVariable Long id) {
        notificationService.readNotice(id, loginUser);
        return ResponseEntity.ok(new ResultResponse(ResultCode.READ_NOTIFICATION_SUCCESS));
    }
}
