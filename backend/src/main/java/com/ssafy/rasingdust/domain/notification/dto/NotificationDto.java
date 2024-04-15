package com.ssafy.rasingdust.domain.notification.dto;

import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class NotificationDto {

    private Long id;
    private Boolean readStatus;
    private NotificationType notificationType;
    private Long receiverId;
    private Long senderId;
    private String senderName;
    private LocalDateTime time;
}
