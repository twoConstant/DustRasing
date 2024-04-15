package com.ssafy.rasingdust.global.result;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ResultCode {
    //Token
    POST_DEVELOP_TOKEN_SUCCESS(201, "개발용 토큰 발급에 성공하였습니다."),

    //User
    GET_USERLIST_SUCCESS(200, "유저리스트 검색에 성공하였습니다."),
    GET_VISITUSER_SUCCESS(200, "해당 유저 페이지 방문에 성공하였습니다."),
    GET_USER_RANK_SUCCESS(200, "해당 유저 랭킹 조회에 성공하였습니다."),
    GET_USER_SUCCESS(200, "해당 유저 조회에 성공하였습니다."),
    //Follow
    CREATE_FOLLOW_SUCCESS(201, "해당 유저 팔로우를 성공하였습니다."),
    DELETE_UNFOLLOW_SUCCESS(201, "해당 유저 언팔로우를 성공하였습니다."),
    GET_FOLLOWINGLIST_SUCCESS(200, "유저의 팔로잉 리스트 조회에 성공하였습니다."),
    GET_FOLLOWERLIST_SUCCESS(200, "유저의 팔로워 리스트 조회에 성공하였습니다."),

    //Charactor
    PUT_FEEDCHARACTER_SUCCESS(200, "해당 유저의 펫 먹이 주기를 성공하였습니다."),

    //Noti
    GET_NOTIFICATION_SUCCESS(200, "알림함 조회에 성공하였습니다."),
    READ_NOTIFICATION_SUCCESS(200, "알림 조회에 성공하였습니다."),

    //Problem
    GET_PROBLEM_SUCCESS(200, "해당 문제 조회에 성공하였습니다."),
    PUT_USER_BOTTLE_SUCCESS(200, "해당 유저의 보유 물병 + 1, 풀이 수 + 1을 성공하였습니다."),

    //Token
    CREATE_ACCESSTOKEN_SUCCESS(201, "AccessToken 생성에 성공하였습니다."),
    ;

    private final int status;
    private final String message;
}
