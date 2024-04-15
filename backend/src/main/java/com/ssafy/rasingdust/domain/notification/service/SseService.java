package com.ssafy.rasingdust.domain.notification.service;

import com.ssafy.rasingdust.domain.notification.dto.SseDto;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

public interface SseService {

    SseEmitter subscribe(String userId, String lastEventId);

    void sendTest(String userId);

    void send(SseDto SseDto);
}
