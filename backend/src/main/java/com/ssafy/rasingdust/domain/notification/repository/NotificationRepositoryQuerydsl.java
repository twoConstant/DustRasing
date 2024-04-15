package com.ssafy.rasingdust.domain.notification.repository;

import com.ssafy.rasingdust.domain.notification.dto.SseDto;
import com.ssafy.rasingdust.domain.user.dto.response.SliceResponse;
import org.springframework.data.domain.Pageable;

public interface NotificationRepositoryQuerydsl {

    SliceResponse<SseDto> getNoticeSliceByUserId(Long userId, Pageable pageable);
}
