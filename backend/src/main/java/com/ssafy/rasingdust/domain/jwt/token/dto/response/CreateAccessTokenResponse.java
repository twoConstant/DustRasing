package com.ssafy.rasingdust.domain.jwt.token.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
@AllArgsConstructor
public class CreateAccessTokenResponse {
    private String accessToken;
}
