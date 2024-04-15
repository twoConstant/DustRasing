package com.ssafy.rasingdust.domain.notification.repository;

import com.ssafy.rasingdust.domain.notification.dto.SseDto;
import java.util.Map;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

public interface SseRepository {

    SseEmitter save(String emitterId, SseEmitter sseEmitter);

    void saveEventCache(String eventId, SseDto event);

    Map<String, SseEmitter> findAllEmitter();

    Map<String, SseEmitter> findAllEmitterStartWithByUserId(String userId);

    Map<String, SseDto> findAllEventCacheStartWithByUserId(String userId);

    void deleteById(String id);

    void deleteAllEmitterStartWithUserId(String userId);

    void deleteAllEventCacheStartWithId(String userId);
}
