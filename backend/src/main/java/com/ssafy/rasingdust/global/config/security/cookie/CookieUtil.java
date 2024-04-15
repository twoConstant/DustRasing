package com.ssafy.rasingdust.global.config.security.cookie;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.SerializationUtils;

import java.io.IOException;
import java.util.Base64;

@Slf4j
public class CookieUtil {
    // 요청값(이름, 값, 만료 기간)을 바탕으로 쿠키 생성
    public static void addCookies(HttpServletResponse response, String name, String value, int maxAge) {
        log.info("쿠키생성");
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true); // HttpOnly 속성 설정 옵션
        cookie.setSecure(true); // HTTPS 통신에서만 쿠키를 전송하도록 설정 옵션
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    // 쿠키의 이름으로 쿠키 해당 쿠키 삭제
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return;
        }

        for (Cookie cookie : cookies) {
            if(name.equals(cookie.getName())) {
                cookie.setValue("");
                cookie.setPath("/");
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }
    }

    // 객체를 직렬화해 쿠키의 값으로 변환
    public static String serialize(Object object) {
        return Base64.getUrlEncoder()
                .encodeToString(SerializationUtils.serialize(object));
    }

    // 쿠키를 역직렬화해 객체로 변환
    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        // 원문 SerializationUtils.deserialize가 deprecated 됨
        return cls.cast(
                SerializationUtils.deserialize(
                        Base64.getUrlDecoder().decode(cookie.getValue())
                )
        );

//        ObjectMapper objectMapper = new ObjectMapper();
//        try {
//            String value = new String(Base64.getUrlDecoder().decode(cookie.getValue()));
//            return objectMapper.readValue(value, cls);
//        } catch (IOException e) {
//            throw new RuntimeException("역직렬화 중 오류 발생", e);
//        }

    }

    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);

        response.addCookie(cookie);
    }
}
