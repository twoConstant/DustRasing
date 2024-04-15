package com.ssafy.rasingdust.global.config.security;

import com.ssafy.rasingdust.domain.user.entity.User;
import com.ssafy.rasingdust.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@RequiredArgsConstructor
@Service
@Slf4j
public class OAuth2UserCustomService extends
    DefaultOAuth2UserService {  // 로드 유저정보로 회원 가입과 이름 수정 서비스

    private final UserRepository userRepository;

    // 해당 loadUser의 이름 필드가 뭐인지?(userName인가 아니면 profile_nickname인가?)
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws
        OAuth2AuthenticationException {
        log.info("activate loadUser");
        // 요청을 바탕으로 유저 정보를 담은 객체를 반환
        OAuth2User oAuth2User = super.loadUser(userRequest);
        saveOrUpdate(oAuth2User);
        return oAuth2User;
    }

    // 유저의 이름을 카카오 닉네임으로 변경 or 없다면 새로 생성
    private User saveOrUpdate(OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();
        // loadUser의 키-벨류 쌍 확인하기
//        System.out.println("loadUser의 키 - 벨류 확인하기(이름 필드가 userName이면 정상)");
//        for (Map.Entry<String, Object> entry : attributes.entrySet()) {
//            String key = entry.getKey();
//            Object value = entry.getValue();
//
//            System.out.println(key + ": " + value);
//        }
//        String email = (String) attributes.get("email");
        // 'properties' 키에 해당하는 값(맵)을 가져옵니다.
        Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");

// 'properties' 맵에서 'nickname' 키에 해당하는 값을 가져옵니다.
        String name = (String) properties.get("nickname");
        String profile = (String) properties.get("profile_image");

        System.out.println("Nickname: " + name);
        System.out.println("ProfileIme : " + profile);
//        System.out.println("email = " + email);
        User user = userRepository.findByUserName(name)
            .map(entity -> entity.updateUserName(name))
            .orElse(User.builder()
                .userName(name)
                .profileImg(profile)
                .build());

        return userRepository.save(user);
    }

}
