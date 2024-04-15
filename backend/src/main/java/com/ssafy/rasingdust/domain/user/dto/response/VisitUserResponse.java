package com.ssafy.rasingdust.domain.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter@Setter
@AllArgsConstructor
@Builder
public class VisitUserResponse {
    private Long id;
    private String userName;
    private String profileImg;
    private int solvedCnt;
    private int bottle;
    private int growthPoint;
    private int rank;
    private boolean isFollowing;
    private boolean isFollower;
}
