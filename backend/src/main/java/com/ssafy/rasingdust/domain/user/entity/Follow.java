package com.ssafy.rasingdust.domain.user.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import jakarta.persistence.UniqueConstraint;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@Getter
@Table(
    name="Follow",

    uniqueConstraints = {
        @UniqueConstraint(
            name = "follow_follower_unique",
            columnNames = {
                "follower_id",
                "following_id"
            }
        )
    }
)
public class Follow {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "follow_id")
    private Long id;

    // 연관관계
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "follower_id")
    private User follower;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "following_id")
    private User following;

    @Transient
    private boolean isFollow;

    @Builder
    public Follow(User follower, User following, boolean isFollow) {
        this.follower = follower;
        this.following = following;
    }

    public void setFollow(boolean follow) {
        isFollow = follow;
    }
}
