package com.ssafy.rasingdust.domain.problem.repository;

import com.ssafy.rasingdust.domain.problem.entity.Trash;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TrashRepository extends JpaRepository<Trash, Long> {
}
