package com.ssafy.rasingdust.domain.jwt.refreshtoken.dto.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateAccessTokenRequest {
    private String refreshToken;
}
