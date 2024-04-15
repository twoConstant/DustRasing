package com.ssafy.rasingdust.global.controlleradvice;

import com.ssafy.rasingdust.global.controlleradvice.dto.ExceptionResponse;
import com.ssafy.rasingdust.global.exception.BusinessLogicException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {


    /**
     * 서버 내부에서 잘못된 비즈니스 로직으로 인해 발생하는 예외처리 핸들러 (500번 에러로 처리)
     * **/
    @ExceptionHandler(BusinessLogicException.class)
    public ResponseEntity<ExceptionResponse> handleBusinessLogicException(final BusinessLogicException e) {
        final ExceptionResponse exceptionResponse = new ExceptionResponse(e.getStatus(), e.getMessage());
        log.error(e.getMessage(), e);

        return ResponseEntity.internalServerError()
            .body(exceptionResponse);
    }
}
