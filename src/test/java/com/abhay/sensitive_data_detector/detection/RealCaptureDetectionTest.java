package com.abhay.sensitive_data_detector.detection;

import com.abhay.sensitive_data_detector.repository.FindingRepository;

import com.abhay.sensitive_data_detector.parser.CapturedRequest;
import com.abhay.sensitive_data_detector.parser.WiresharkJsonParser;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RealCaptureDetectionTest {

    @Test
    void detectsSensitiveDataFromRealCapture() throws Exception {

        WiresharkJsonParser parser = new WiresharkJsonParser();
        FindingRepository repository = org.mockito.Mockito.mock(FindingRepository.class);
        DetectionService detector = new DetectionService(repository);

        List<Finding> allFindings = new ArrayList<>();

        try (InputStream in =
                     Files.newInputStream(Path.of("evidence/capture.json"))) {

            List<CapturedRequest> requests = parser.parse(in);

            for (CapturedRequest request : requests) {
                allFindings.addAll(detector.detect(request));
            }
        }

        System.out.println("Findings found: " + allFindings.size());

        for (Finding finding : allFindings) {
            System.out.println(
                    finding.type()
                            + " | "
                            + finding.severity()
                            + " | "
                            + finding.maskedValue()
                            + " | frame="
                            + finding.frameNumber()
            );
        }

        assertTrue(allFindings.stream()
                .anyMatch(f -> f.type().equals("API_KEY")));

        assertTrue(allFindings.stream()
                .anyMatch(f -> f.type().equals("PASSWORD")));

        assertTrue(allFindings.stream()
                .anyMatch(f -> f.type().equals("API_KEY")
                        && f.severity().equals("CRITICAL")));

        assertTrue(allFindings.stream()
                .anyMatch(f -> f.type().equals("PASSWORD")
                        && f.severity().equals("CRITICAL")));

        assertTrue(allFindings.stream()
                .anyMatch(f -> f.type().equals("BEARER_TOKEN")
                        && f.severity().equals("HIGH")));

        assertTrue(allFindings.stream()
                .anyMatch(f -> f.type().equals("EMAIL")
                        && f.severity().equals("MEDIUM")));
    }
}
