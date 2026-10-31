package com.abhay.sensitive_data_detector.repository;



import com.abhay.sensitive_data_detector.entity.FindingEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<FindingEntity, Long> {


}
