package com.ssafy.rasingdust.domain.notification.entity;

import com.ssafy.rasingdust.domain.notification.dto.NotificationType;
import com.ssafy.rasingdust.domain.user.entity.User;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class Notification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Boolean readStatus;
    @Enumerated(value = EnumType.STRING)
    private NotificationType notificationType;
    private Long receiverId;
    @ManyToOne(fetch = FetchType.LAZY)
    private User sender;
    private LocalDateTime time;

    public void updateReadStatus(Boolean status) {
        this.readStatus = status;
    }

    public static Notification of(NotificationType notificationType, Long receiverId, User sender,
        LocalDateTime time) {
        return builder()
            .readStatus(false)
            .notificationType(notificationType)
            .receiverId(receiverId)
            .sender(sender)
            .time(time)
            .build();
    }
}
