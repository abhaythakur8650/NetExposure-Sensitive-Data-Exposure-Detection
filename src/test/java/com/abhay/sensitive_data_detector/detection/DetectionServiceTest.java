package com.abhay.sensitive_data_detector.detection;




import com.abhay.sensitive_data_detector.parser.CapturedRequest;
import org.junit.jupiter.api.Test;
import com.abhay.sensitive_data_detector.repository.FindingRepository;
import org.mockito.Mockito;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DetectionServiceTest {

    @Test
    void detectsApiKeyAndPassword() {

        FindingRepository repository = org.mockito.Mockito.mock(FindingRepository.class);


        DetectionService service = new DetectionService(repository);


        CapturedRequest request = new CapturedRequest(
                20340,
                "test-time",
                "127.0.0.1",
                "127.0.0.1",
                "8080",
                false,
                "POST",
                "/api/test/login",
                """
                POST /api/test/login HTTP/1.1
                Content-Type: application/json

                {"username":"testuser","password":"FakePass@123"}
                api_key=FAKE-API-KEY-1234567890
                """
        );

        List<Finding> findings = service.detect(request);

        assertEquals(2, findings.size());

        assertTrue(findings.stream()
                .anyMatch(f -> f.type().equals("PASSWORD")));

        assertTrue(findings.stream()
                .anyMatch(f -> f.type().equals("API_KEY")));

        assertTrue(findings.stream()
                .allMatch(f -> f.severity().equals("CRITICAL")));

        assertTrue(findings.stream()
                .noneMatch(f ->
                        f.maskedValue().contains("FakePass@123")
                                || f.maskedValue().contains("FAKE-API-KEY-1234567890")));
    }
}