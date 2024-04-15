package com.ssafy.rasingdust.domain.problem.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class AddBottleResponse {
    private int bottle;
    private int solvedCnt;
    private int rank;

}
