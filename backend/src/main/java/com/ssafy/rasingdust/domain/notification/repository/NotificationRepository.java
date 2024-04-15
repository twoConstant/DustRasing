package com.ssafy.rasingdust.domain.notification.repository;

import com.ssafy.rasingdust.domain.notification.entity.Notification;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NotificationRepository extends JpaRepository<Notification, Long>,
    NotificationRepositoryQuerydsl {

    List<Notification> findAllByReceiverIdOrderByTimeDesc(Long userId);

    Integer countByReceiverIdAndReadStatusIsFalse(Long receiverId);
}
