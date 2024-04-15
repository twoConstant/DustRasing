package com.ssafy.rasingdust.domain.user.dto.response;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter@Setter
@AllArgsConstructor
@Builder
public class GetUserResponse {
    private Long id;
    private String userName;
    private String profileImg;
    private int solvedCnt;
    private int bottle;
    private int growthPoint;
    private int rank;
}
