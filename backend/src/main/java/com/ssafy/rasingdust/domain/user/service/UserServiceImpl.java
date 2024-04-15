package com.ssafy.rasingdust.domain.user.service;

import static com.ssafy.rasingdust.domain.notification.dto.NotificationType.KOCK_ACTION;

import com.ssafy.rasingdust.domain.notification.dto.NotificationType;
import com.ssafy.rasingdust.domain.notification.service.NotificationService;
import com.ssafy.rasingdust.domain.user.dto.request.AddUserRequest;
import com.ssafy.rasingdust.domain.user.dto.response.FeedCharacterResponse;
import com.ssafy.rasingdust.domain.user.dto.response.GetUserResponse;
import com.ssafy.rasingdust.domain.user.dto.response.SliceResponse;
import com.ssafy.rasingdust.domain.user.dto.response.UserDto;
import com.ssafy.rasingdust.domain.user.dto.response.UserListDto;
import com.ssafy.rasingdust.domain.user.dto.response.VisitUserResponse;
import com.ssafy.rasingdust.domain.user.entity.Follow;
import com.ssafy.rasingdust.domain.user.entity.User;
import com.ssafy.rasingdust.domain.user.repository.FollowRepository;
import com.ssafy.rasingdust.domain.user.repository.UserRepository;
import com.ssafy.rasingdust.global.exception.BusinessLogicException;
import com.ssafy.rasingdust.global.exception.ErrorCode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final FollowRepository followRepository;
    private final NotificationService notificationService;

    @Override
    public User findById(Long userId) {
        return userRepository.findById(userId)
            .orElseThrow(() -> new BusinessLogicException(ErrorCode.USER_NOT_FOUND));
    }

    @Override
    public User findByUserName(String name) {
        return userRepository.findByUserName(name)
            .orElseThrow(() -> new BusinessLogicException(ErrorCode.USER_NOT_FOUND));
    }

    @Override
    public SliceResponse findByuserNameStartsWith(Long userId, String userName, Pageable pageable) {

        //현재 로그인한 유저의 팔로잉 리스트 조회
        List<User> currentUserFollowingList = followRepository.findByFollowings(userId);

        //condition == 현재 유저의 팔로잉 리스트
        List<Long> condition = new ArrayList<>();

        if (!currentUserFollowingList.isEmpty()) {
            for (int i = 0; i < currentUserFollowingList.size() - 1; i++) {
                User user = currentUserFollowingList.get(i);
                condition.add(user.getId());
            }
            condition.add(currentUserFollowingList.getLast().getId());
        }

        Slice<UserListDto> result = userRepository.searchUser(condition, userName, userId,
            pageable);

        /**
         * 현재 로그인 한 유저와 동시에 팔로우 하고있는 유저들 중 대표되는 한 유저의 닉네임 조회
         * **/
        for (UserListDto user : result) {
            if (user.getFollowCnt() > 0) {
                user.setDuplicateFollower(userRepository.findByCondition(condition, user.getId()));
            }
        }

        // 비검사 경고 제거 필요
        SliceResponse resultDto = new SliceResponse(result);

        return resultDto;
    }


    // 유저 생성 메서드
    @Override
    public Long save(AddUserRequest addUserRequestDto) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        return userRepository.save(
                User.builder()
                    .build())
            .getId();


    }

    @Override
    public void followUser(Long toId, Long fromId) {

        //예외처리 : 자기 자신을 팔로우하려는 경우
        if (toId.equals(fromId)) {
            throw new BusinessLogicException(ErrorCode.FOLLOW_BAD_REQUEST);
        }

        Follow follow = Follow.builder()
            .follower(userRepository.findById(toId)
                .orElseThrow(() -> new BusinessLogicException(ErrorCode.USER_NOT_FOUND)))
            .following(userRepository.findById(fromId)
                .orElseThrow(() -> new BusinessLogicException(ErrorCode.USER_NOT_FOUND)))
            .build();

        //유니크 제약조건 예외 방지를 위한 체크 로직 추가
        Optional<Follow> isFollowExist = Optional.ofNullable(
            followRepository.followIsExist(toId, fromId));

        if (isFollowExist.isPresent()) {
            throw new BusinessLogicException(ErrorCode.FOLLOW_ALREADY_EXIST);
        }

        followRepository.save(follow);
        notificationService.saveNotice(NotificationType.FOLLOW_EVENT, fromId, toId);
    }

    @Override
    public void unFollowUser(Long toId, Long fromId) {

        //예외처리 : 팔로우 관계가 존재하지 않는 경우
        Optional<Follow> isFollowExist = Optional.ofNullable(
            followRepository.followIsExist(toId, fromId));

        if (isFollowExist.isEmpty()) {
            throw new BusinessLogicException(ErrorCode.FOLLOW_NOT_FOUND);
        }

        Follow follow = isFollowExist.get();
        followRepository.deleteById(follow.getId());

    }

    /**
     * 내 팔로우 목록을 조회할 경우 맞팔 Status를 체크할 필요 없음. 다른 사람의 팔로우 목록을 조회할 경우 맞팔 Status 체크 로직 추가
     **/
    @Override
    public SliceResponse getFollowingList(Long myId, Long userId, Pageable pageable) {

        Optional<User> user = userRepository.findById(userId);

        Optional<User> currentUser = userRepository.findById(myId);

        //예외처리 : 유저가 존재하지 않는 경우
        if (user.isEmpty() || currentUser.isEmpty()) {
            throw new BusinessLogicException(ErrorCode.USER_NOT_FOUND);
        }

        //해당 유저의 팔로잉리스트를 조회
        Slice<UserDto> result = followRepository.findByFollowing(user.get().getId(), pageable);

        /**다른 유저의 팔로잉 리스트를 조회할 경우
         * 다른 유저의 팔로워들이 현재 유저를 팔로우하고 있는지 체크
         * 다른 유저가 팔로우하고 있는 사람이 현재 로그인한 유저도 팔로우 하고있다면 true값 세팅
         * 현재 로그인 한 유저가 팔로잉 리스트에 포함되는 경우 제거해서 반환
         * */
        if (!userId.equals(myId)) {
            //로그인한 유저의 팔로우 리스트
            List<UserDto> currentUserFollowList = followRepository.findByFollowing(myId);

            for (UserDto follow : result) {
                if (currentUserFollowList.contains(follow)) {
                    follow.setFollow(true);
                }
            }
        } else {
            //현재 로그인 한 유저와 조회하려는 유저가 같을 경우 모드 true
            for (UserDto follow : result) {
                follow.setFollow(true);
            }
        }

        // isFollow 기준으로 정렬
        List<UserDto> sortedList = result.getContent().stream()
            .sorted(Comparator.comparing(userDto -> userDto.isFollow() ? 0 : 1))
            .collect(Collectors.toList());

        Slice<UserDto> orderedResponse = new SliceImpl(sortedList, pageable, result.hasNext());

        SliceResponse response = new SliceResponse(orderedResponse);

        return response;
    }

    @Override
    public SliceResponse getFollowerList(Long myId, Long userId, Pageable pageable) {

        Optional<User> user = userRepository.findById(userId);

        Optional<User> currentUser = userRepository.findById(myId);

        //예외처리 : 유저가 존재하지 않는 경우
        if (user.isEmpty() || currentUser.isEmpty()) {
            throw new BusinessLogicException(ErrorCode.USER_NOT_FOUND);
        }

        //해당 유저의 팔로워리스트를 조회
        Slice<UserDto> result = followRepository.findByFollower(user.get().getId(), pageable);

        /**다른 유저의 팔로워 리스트를 조회할 경우
         * 다른 유저의 팔로워들이 현재 로그인한 유저가 팔로우 하고있는지 체크
         * 팔로잉 리스트 조회 비즈니스 로직과 동일
         * */
        if (!userId.equals(myId)) {
            List<UserDto> currentUserFollowingList = followRepository.findByFollowing(
                myId);   //로그인한 유저의 팔로우 리스트

            for (UserDto follow : result.getContent()) {
                if (currentUserFollowingList.contains(follow)) {
                    follow.setFollow(true);
                }
            }
        } else {
            //현재 로그인 한 유저와 조회하려는 유저가 같을 경우 모드 true
            for (UserDto follow : result) {
                follow.setFollow(true);
            }
        }

        // isFollow 기준으로 정렬
        List<UserDto> sortedList = result.getContent().stream()
            .sorted(Comparator.comparing(userDto -> userDto.isFollow() ? 0 : 1))
            .collect(Collectors.toList());

        Slice<UserDto> orderedResponse = new SliceImpl(sortedList, pageable, result.hasNext());

        SliceResponse response = new SliceResponse(orderedResponse);

        return response;
    }

    @Override
    @Transactional
    public FeedCharacterResponse feedCharacter(Long userId) {
        User findUser = userRepository.findById(userId)
            .orElseThrow(() -> new BusinessLogicException(ErrorCode.USER_NOT_FOUND));
        findUser.feedCharacter();
        int rank = getUserRank(findUser.getId());
        return FeedCharacterResponse.builder()
            .bottle(findUser.getBottle())
            .growthPoint(findUser.getGrowthPoint())
            .rank(rank)
            .build();
    }

    @Override
    public VisitUserResponse visitUser(Long visitorId, Long invitorId) {
        User invitor = userRepository.findById(invitorId)
            .orElseThrow(() -> new BusinessLogicException(ErrorCode.USER_NOT_FOUND));
        boolean isFollowing = false;
        boolean isFollower = false;
        int invitorRank = getUserRank(invitorId);

        List<Long> followerList = invitor.getFollowerList().stream()
            .map((follow) -> follow.getFollowing().getId())
            .toList();

        List<Long> followingList = invitor.getFollowingList().stream()
            .map((follow -> follow.getFollower().getId()))
            .toList();
        for (Long followerId : followerList) {
            if (followerId.equals(visitorId)) {
                isFollower = true;
                break;
            }
        }

        for (Long followingId : followingList) {
            if (followingId.equals(visitorId)) {
                isFollowing = true;
                break;
            }
        }

        return VisitUserResponse.builder()
            .id(invitor.getId())
            .userName(invitor.getUsername())
            .profileImg(invitor.getProfileImg())
            .solvedCnt(invitor.getSolvedCnt())
            .bottle(invitor.getBottle())
            .growthPoint(invitor.getGrowthPoint())
            .rank(invitorRank)
            .isFollowing(isFollowing)
            .isFollower(isFollower)
            .build();
    }

    @Override
    public int getUserRank(Long userId) {
        User user = findById(userId);
        return userRepository.countWithGrowthPointGreaterThan(user.getGrowthPoint()) + 1;
    }

    @Override
    public GetUserResponse getUser(Long userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new BusinessLogicException(ErrorCode.USER_NOT_FOUND));
        int rank = getUserRank(userId);

        return GetUserResponse.builder()
            .id(user.getId())
            .userName(user.getUsername())
            .profileImg(user.getProfileImg())
            .solvedCnt(user.getSolvedCnt())
            .bottle(user.getBottle())
            .growthPoint(user.getGrowthPoint())
            .rank(rank)
            .build();
    }

    @Override
    public void sendKock(Long id, Long userId) {
        notificationService.saveNotice(KOCK_ACTION, userId, id);
    }

}
