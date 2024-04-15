package com.ssafy.rasingdust.domain.notification.service;

import com.ssafy.rasingdust.domain.notification.dto.NotificationType;
import com.ssafy.rasingdust.domain.notification.dto.SseDto;
import com.ssafy.rasingdust.domain.notification.entity.Notification;
import com.ssafy.rasingdust.domain.user.dto.response.SliceResponse;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;

public interface NotificationService {

    Notification saveNotice(NotificationType notificationType, Long receiverId,
        Long senderId);

    SliceResponse<SseDto> getNoticeList(UserDetails loginUser, Pageable pageable);

    void readNotice(Long id, UserDetails loginUser);
}
