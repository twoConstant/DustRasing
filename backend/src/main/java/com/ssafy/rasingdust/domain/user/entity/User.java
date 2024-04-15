package com.ssafy.rasingdust.domain.user.entity;

import com.ssafy.rasingdust.global.exception.BusinessLogicException;
import com.ssafy.rasingdust.global.exception.ErrorCode;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "member")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(name = "user_name", unique = true)
    private String userName;

    @Lob
    @Column(columnDefinition = "MEDIUMTEXT")
    private String profileImg;

    @Column(name = "create_date", nullable = false, updatable = false)
    private LocalDateTime createDate = LocalDateTime.now();

    @Column(name = "solved_cnt", nullable = false)
    private int solvedCnt = 0;

    @Column(name = "bottle", nullable = false)
    private int bottle = 0;

    @Column(name = "growth_point", nullable = false)
    private int growthPoint = 0;

    @Transient
    private boolean isFollow;

    @Builder
    public User(String userName, String profileImg) {
        this.userName = userName;
        this.profileImg = profileImg;
    }



    // 팔로우 테이블 연관
    // 사용자가 팔로우하는 관계
    @OneToMany(mappedBy = "follower", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Follow> followerList = new ArrayList<>();

    // 사용자를 팔로우하는 관계
    @OneToMany(mappedBy = "following", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Follow> followingList = new ArrayList<>();

    // 사용자 이름 수정 메서드
    public User updateUserName(String userName) {
        this.userName = userName;
        return this;
    }

    public void feedCharacter() {
        // 물병 1개 이상인가?
        if(this.getBottle() < 1) {throw new BusinessLogicException(ErrorCode.USER_NOT_ENOUGH_BOTTLE);}

        // 물병에서 -1
        int curBottleCnt = this.getBottle();
        this.setBottle(curBottleCnt - 1);
        // 캐릭터 성장 포인트 + 1
        int currGrowthPoint = this.getGrowthPoint();
        this.setGrowthPoint(currGrowthPoint + 1);
    }

    public void addBottle() {
        this.bottle += 1;
        this.solvedCnt += 1;
    }

    // 이후 권한이 여러가지 생기면 추가해야됨
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("user"));
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
