package com.ssafy.rasingdust.domain.user.repository;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.Expression;
import com.querydsl.core.types.ExpressionUtils;
import com.querydsl.core.types.Order;
import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.core.types.Projections;
import com.querydsl.jpa.JPAExpressions;
import com.ssafy.rasingdust.domain.user.dto.response.UserListDto;
import com.ssafy.rasingdust.domain.user.entity.QUser;
import java.util.List;

import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;

import static com.ssafy.rasingdust.domain.user.entity.QUser.user;
import static com.ssafy.rasingdust.domain.user.entity.QFollow.follow;

@Slf4j
public class UserRepositoryImpl implements UserRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    public UserRepositoryImpl(EntityManager em) {
        this.queryFactory = new JPAQueryFactory(em);
    }

    @Override
    public Slice<UserListDto> searchUser(List<Long> condition, String userName, Long currentUser, Pageable pageable) {

        QUser userAlias = new QUser("userAlias");

        int pageSize = pageable.getPageSize();

        Expression<Long> followCountSubquery = JPAExpressions
            .select(userAlias.userName.count())
            .from(userAlias)
            .innerJoin(follow).on(userAlias.id.eq(follow.follower.id))
            .where(follow.follower.id.in(condition)
                .and(follow.following.id.eq(user.id)));

        BooleanBuilder predicate = new BooleanBuilder();
        predicate.and(user.id.ne(currentUser));


        List<UserListDto> result = queryFactory
            .select(Projections.fields(UserListDto.class, user.id.as("id"),
                user.userName.as("userName"),
                user.growthPoint.as("growthPoint"),
                user.solvedCnt.as("solvedCnt"),
                user.profileImg.as("profileImg"),
                ExpressionUtils.as(
                    followCountSubquery, "followCnt"
                )
            ))
            .from(user)
            .where(user.userName.likeIgnoreCase("%" + userName + "%")
                .and(predicate))
            .offset(pageable.getOffset())
            .limit(pageSize + 1)
            .orderBy(new OrderSpecifier<>(Order.DESC, followCountSubquery))
            .fetch();

        boolean hasNext = false;
        if (result.size() > pageSize) {
            result.remove(pageSize);
            hasNext = true;
        }

        //Slice 객체 변환
        Slice<UserListDto> sliceResult = new SliceImpl(result, pageable, hasNext);


        return sliceResult;
    }

}
