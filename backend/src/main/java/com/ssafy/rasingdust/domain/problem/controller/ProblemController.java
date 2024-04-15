package com.ssafy.rasingdust.domain.problem.controller;

import com.ssafy.rasingdust.domain.problem.dto.response.AddBottleResponse;
import com.ssafy.rasingdust.domain.problem.dto.response.GetProblemResponse;
import com.ssafy.rasingdust.domain.problem.entity.Trash;
import com.ssafy.rasingdust.domain.problem.repository.TrashRepository;
import com.ssafy.rasingdust.domain.problem.service.ProblemService;
import com.ssafy.rasingdust.domain.problem.service.ProblemServiceImpl;
import com.ssafy.rasingdust.domain.user.entity.User;
import com.ssafy.rasingdust.domain.user.service.UserService;
import com.ssafy.rasingdust.global.result.ResultCode;
import com.ssafy.rasingdust.global.result.ResultResponse;
import jakarta.annotation.PostConstruct;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/problem")
@RequiredArgsConstructor
@Slf4j
public class ProblemController implements ProblemControllerDocs{

    private final ProblemService problemService;

    //
    @GetMapping()
    public ResponseEntity<ResultResponse> getProblem(@RequestParam(name = "number") Long number) {
        log.info("number : " + number);
        GetProblemResponse response = problemService.getProblem(number);
        return ResponseEntity.ok(new ResultResponse(ResultCode.GET_PROBLEM_SUCCESS, response));
    }

    @PutMapping()
    public ResponseEntity<ResultResponse> addBottle(@AuthenticationPrincipal UserDetails userDetails) {
        AddBottleResponse response = problemService.addBottle(Long.valueOf(userDetails.getUsername()));
        return ResponseEntity.ok(new ResultResponse(ResultCode.PUT_USER_BOTTLE_SUCCESS, response));
    }

}
