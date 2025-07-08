package com.cos.jwt.repository;

import com.cos.jwt.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Member findByUsername(String username);
}
