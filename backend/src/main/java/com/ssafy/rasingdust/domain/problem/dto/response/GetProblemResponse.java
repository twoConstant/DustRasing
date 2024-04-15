package com.ssafy.rasingdust.domain.problem.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class GetProblemResponse {
    private String correct;
    private String dummy1;
    private String dummy2;
}
