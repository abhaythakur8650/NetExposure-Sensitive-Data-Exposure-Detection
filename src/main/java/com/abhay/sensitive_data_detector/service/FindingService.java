package com.abhay.sensitive_data_detector.service;



import com.abhay.sensitive_data_detector.detection.Finding;
import com.abhay.sensitive_data_detector.entity.FindingEntity;
import com.abhay.sensitive_data_detector.repository.FindingRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FindingService {

    private final FindingRepository repository;

    public FindingService(FindingRepository repository) {
        this.repository = repository;
    }

    public void saveFindings(List<Finding> findings) {


        repository.deleteAll();
        for (Finding finding : findings) {

            FindingEntity entity = new FindingEntity(
                    finding.type(),
                    finding.severity(),
                    finding.maskedValue(),
                    finding.frameNumber(),
                    finding.method(),
                    finding.uri()
            );


            repository.save(entity);
        }
    }

    public List<FindingEntity> getAllFindings() {
        return repository.findAll();
    }
}
