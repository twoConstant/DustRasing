package com.ssafy.rasingdust.domain.notification.service;

import static com.ssafy.rasingdust.domain.notification.dto.NotificationType.TEST_MSG;

import com.ssafy.rasingdust.domain.notification.dto.NotificationType;
import com.ssafy.rasingdust.domain.notification.dto.SseDto;
import com.ssafy.rasingdust.domain.notification.repository.SseRepository;
import com.ssafy.rasingdust.domain.user.repository.UserRepository;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Service
@Slf4j
@RequiredArgsConstructor
public class SseServiceImpl implements SseService {

    private static final Long DEFAULT_TIMEOUT = 60L * 1000 * 5;
    private static final Long REDIRECT_TIME = 5L * 1000;
    //    private final RedisOperations<String, NotificationDto> eventRedisOperations;
//    private final RedisMessageListenerContainer redisMessageListenerContainer;
    final UserRepository userRepository;
    private final SseRepository sseRepository;

    @Override
    public SseEmitter subscribe(String userId, String lastEventId) {
        String emitterId = makeTimeIncludeId(userId);
        SseEmitter emitter = sseRepository.save(emitterId, new SseEmitter(DEFAULT_TIMEOUT));

        // emitter의 상태를 체크함, 완료되었는지 타임아웃이 났는지
        checkEmitterStatus(emitter, emitterId);

        // 503 에러 방지 더미 이벤트 전송
        SseDto sseDto = SseDto.of(NotificationType.SSE_CONNECT,
            Long.valueOf(userId), LocalDateTime.now());
        sendSse(emitter, emitterId, emitterId, sseDto);

        // 클라이언트가 미수신한 Event 전송
        if (hasLostData(lastEventId)) {
            sendLostData(lastEventId, userId, emitterId, emitter);
        }

        return emitter;
    }

    @Override
    public void sendTest(String userId) {
        SseDto sseDto = SseDto.of(TEST_MSG, Long.valueOf(userId), LocalDateTime.now());
        send(sseDto);
    }

    @Override
    //특정 유저에게 알림 전송
    public void send(SseDto SseDto) {

        // 로그인 한 유저의 SseEmitter 모두 가져오기
        Map<String, SseEmitter> sseEmitters = sseRepository.findAllEmitterStartWithByUserId(
            String.valueOf(SseDto.getReceiverId()));

        sseEmitters.forEach(
            (key, emitter) -> {
                // 데이터 캐시 저장(유실된 데이터 처리하기 위함)
                sseRepository.saveEventCache(key, SseDto);
                // 데이터 전송
                sendSse(emitter, makeTimeIncludeId(String.valueOf(SseDto.getReceiverId())),
                    key, SseDto);
            }
        );
    }

    //    @Transactional(propagation = Propagation.REQUIRES_NEW)
//    @TransactionalEventListener
//    //실질적으로 알림을 저장하고 redis 채널에 메시지를 publish하는 역할
//    public void send(NotificationDto NotificationDto) {
//        eventRedisOperations.convertAndSend(getTopicName(NotificationDto.getUserId()),
//            NotificationDto);
//    }
    private void sendLostData(String lastEventId, String userId, String emitterId,
        SseEmitter emitter) {

        Map<String, SseDto> eventCaches = sseRepository.findAllEventCacheStartWithByUserId(
            userId);
        eventCaches.entrySet().stream()
            .filter(entry -> lastEventId.compareTo(entry.getKey()) < 0)
            .forEach(
                entry -> sendSse(emitter, entry.getKey(), emitterId, entry.getValue()));
    }

    //종료 상태
    private void checkEmitterStatus(SseEmitter emitter, String emitterId) {
        emitter.onCompletion(() -> {
            sseRepository.deleteById(emitterId);
            //redisMessageListenerContainer.removeMessageListener(messageListener);
        });
        emitter.onTimeout(() -> {
            sseRepository.deleteById(emitterId);
            //redisMessageListenerContainer.removeMessageListener(messageListener);
        });
        emitter.onError((e) -> sseRepository.deleteById(emitterId));
    }

    private void sendSse(SseEmitter emitter, String eventId, String emitterId,
        SseDto dto) {

        try {
            emitter.send(SseEmitter.event()
                .id(eventId)
                .reconnectTime(REDIRECT_TIME)
                .name(dto.getEvent())
                .data(dto));
        } catch (IOException exception) {
            sseRepository.deleteById(emitterId);
            emitter.completeWithError(exception);
        }
    }

//    private String getTopicName(final String userId) {
//        return "topics:" + userId;
//    }

    private String makeTimeIncludeId(String userId) {
        return userId + "_" + System.currentTimeMillis();
    }

    private boolean hasLostData(String lastEventId) {
        return !lastEventId.isEmpty();
    }
}