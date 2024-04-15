package com.ssafy.rasingdust.domain.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class FeedCharacterResponse {
    // 물병, 성장 포인트
    private int bottle;
    private int growthPoint;
    private int rank;
}
