package com.ssafy.rasingdust.domain.user.repository;

import com.ssafy.rasingdust.domain.user.entity.User;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long>, UserRepositoryCustom {
    Optional<User> findById(long userId);

    Optional<User> findByUserName(String name);

    @Query("SELECT COUNT(u) FROM User u WHERE u.growthPoint > :growthPoint")
    int countWithGrowthPointGreaterThan(@Param("growthPoint") int growthPoint);

    @Query(value = "SELECT u.userName FROM Follow f INNER JOIN User u ON f.follower.id = u.id WHERE f.following.id = :userId AND f.follower.id IN(:condition) ORDER BY u.userName LIMIT 1")
    String findByCondition(@Param("condition") List<Long> condition, @Param("userId") Long userId);

}
