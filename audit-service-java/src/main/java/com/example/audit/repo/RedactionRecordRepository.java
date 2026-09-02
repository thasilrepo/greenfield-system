package com.example.audit.repo;

import com.example.audit.model.RedactionRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RedactionRecordRepository extends JpaRepository<RedactionRecord, Long> {
    List<RedactionRecord> findByTargetRecordIdOrderByIdDesc(Long targetRecordId);
}
