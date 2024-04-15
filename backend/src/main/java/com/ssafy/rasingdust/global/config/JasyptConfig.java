package com.ssafy.rasingdust.global.config;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JasyptConfig {

    @Value("${encryptor.key}")
    String KEY;

    private static final String ALGORITHM = "PBEWithMD5AndDES";

    @Bean(name = "jasyptStringEncryptor")
    public StringEncryptor stringEncryptor() {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();

        config.setPassword(KEY);    //암호화 시 사용할 키 -> 이 키를 가지고 암호화 복호화 진행
        config.setAlgorithm(ALGORITHM); //사용할 알고리즘
        config.setKeyObtentionIterations("1000");   //반복할 해싱 회수
        config.setPoolSize("1");    //pool 크기
        config.setProviderName("SunJCE");   //사용할 암호화 라이브러리
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");    //salt 생성 클래스
        config.setStringOutputType("base64");   //인코딩 방식
        encryptor.setConfig(config);    //설정 주입

        return encryptor;
    }
}
