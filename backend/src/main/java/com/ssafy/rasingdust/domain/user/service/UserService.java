package com.ssafy.rasingdust.domain.user.service;

import com.ssafy.rasingdust.domain.user.dto.request.AddUserRequest;
import com.ssafy.rasingdust.domain.user.dto.response.FeedCharacterResponse;
import com.ssafy.rasingdust.domain.user.dto.response.GetUserResponse;
import com.ssafy.rasingdust.domain.user.dto.response.SliceResponse;
import com.ssafy.rasingdust.domain.user.dto.response.VisitUserResponse;
import com.ssafy.rasingdust.domain.user.entity.User;
import org.springframework.data.domain.Pageable;

public interface UserService {

    public User findById(Long userId);

    public User findByUserName(String name);

    public SliceResponse findByuserNameStartsWith(Long userId, String userName, Pageable pageable);

    public Long save(AddUserRequest addUserRequestDto);

    public void followUser(Long toId, Long fromId);

    public void unFollowUser(Long toId, Long fromId);

    public SliceResponse getFollowingList(Long myId, Long userId, Pageable pageable);

    public SliceResponse getFollowerList(Long myId, Long userId, Pageable pagealbe);

    public FeedCharacterResponse feedCharacter(Long userId);

    public VisitUserResponse visitUser(Long visitorId, Long invitorId);

    public int getUserRank(Long userId);

    public GetUserResponse getUser(Long userId);

    void sendKock(Long aLong, Long userId);
}
