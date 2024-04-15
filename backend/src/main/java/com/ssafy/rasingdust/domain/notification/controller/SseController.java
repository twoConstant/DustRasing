package com.ssafy.rasingdust.domain.notification.controller;


import com.ssafy.rasingdust.domain.notification.service.SseService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequestMapping("/sse")
@RequiredArgsConstructor
@Tag(name = "SSEController", description = "SSE 연결 관련")
public class SseController {

    private final SseService sseService;

    @Operation(summary = "SSE 연결")
    @GetMapping(value = "/subscribe", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public ResponseEntity<SseEmitter> subscribe(@AuthenticationPrincipal UserDetails loginUser,
        @RequestHeader(value = "Last-Event-ID", required = false, defaultValue = "") String lastEventId,
        HttpServletResponse response) {
        SseEmitter emitter = sseService.subscribe(loginUser.getUsername(), lastEventId);
        response.setHeader("X-Accel-Buffering", "no");
        return ResponseEntity.ok(emitter);
    }

    @Operation(summary = "SSE로 테스트 메시지 전달")
    @PostMapping("/send/{userId}")
    public ResponseEntity<Void> sendData(@PathVariable String userId) {
        sseService.sendTest(userId);
        return ResponseEntity.ok().build();
    }
}
