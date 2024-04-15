package com.ssafy.rasingdust.domain.user.repository;


import com.ssafy.rasingdust.domain.user.dto.response.UserListDto;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;

public interface UserRepositoryCustom {
    Slice<UserListDto> searchUser(List<Long> condition, String userName, Long currentUser, Pageable pageable);
}
