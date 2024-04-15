package com.ssafy.rasingdust.global.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode {

    // Global
    INTERNAL_SERVER_ERROR(500, "내부 서버 오류입니다."),
    METHOD_NOT_ALLOWED(405, "허용되지 않은 HTTP method입니다."),
    INPUT_VALUE_INVALID(400, "유효하지 않은 입력입니다."),
    INPUT_TYPE_INVALID(400, "입력 타입이 유효하지 않습니다."),
    HTTP_MESSAGE_NOT_READABLE(400, "request message body가 없거나, 값 타입이 올바르지 않습니다."),
    HTTP_HEADER_INVALID(400, "request header가 유효하지 않습니다."),
    ENTITY_NOT_FOUNT(500, "존재하지 않는 Entity입니다."),
    FORBIDDEN_ERROR(403, "작업을 수행하기 위한 권한이 없습니다."),

    //토큰 관련
    USER_DEVELOP_TOKEN_CONFLICT(409, "이미 개발용 토큰이 존재하는 유저입니다."),
    ACCESSTOKEN_DURATION_EXPIRED(401, "AccessToken이 만료되었습니다."),
    REFRESHTOKEN_DURATION_EXPIRED(401, "RefreshToken이 만료되었습니다."),
    INVAILED_ACCESSTOEKN(403, "유효하지 않은 AccessToken입니다."),
    INVAILED_REFRESHTOKEN(403, "유효하지 않은 RefreshToken입니다."),


    //팔로우 관련
    FOLLOW_ALREADY_EXIST(3000, "이미 팔로잉 되어있는 회원입니다."),
    FOLLOW_NOT_FOUND(3000, "팔로잉 되어있지 않은 회원입니다."),
    FOLLOW_BAD_REQUEST(4004, "자기 자신은 팔로우할 수 없습니다."),

    //회원 관련
    USER_NOT_FOUND(404, "해당하는 회원이 존재하지 않습니다."),
    USER_NOT_ENOUGH_BOTTLE(422, "사용 할 수 있는 물병이 없습니다."),

    //문제 관련
    NUMBER_NOT_FOUND(404, "존재하지 않은 분류코드입니다.")

    ;

    private final int status;
    private final String message;
}
