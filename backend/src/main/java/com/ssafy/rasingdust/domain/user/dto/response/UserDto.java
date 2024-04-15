package com.ssafy.rasingdust.domain.user.dto.response;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

@Data
public class UserDto {
    private Long id;
    private String userName;
    private LocalDateTime createDate;
    private int solvedCnt;
    private int bottle;
    private int growthPoint;
    private String profileImg;
    private boolean isFollow;

    @Builder
    public UserDto(Long id, String userName, LocalDateTime createDate, int solvedCnt, int bottle,
        int growthPoint, String profileImg) {
        this.id = id;
        this.userName = userName;
        this.createDate = createDate;
        this.solvedCnt = solvedCnt;
        this.bottle = bottle;
        this.growthPoint = growthPoint;
        this.profileImg = profileImg;
    }

}
