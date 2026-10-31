package com.abhay.sensitive_data_detector.controller;





import com.abhay.sensitive_data_detector.detection.DetectionService;
import com.abhay.sensitive_data_detector.detection.Finding;
import com.abhay.sensitive_data_detector.parser.CapturedRequest;
import com.abhay.sensitive_data_detector.parser.PdfTextExtractor;
import com.abhay.sensitive_data_detector.parser.WiresharkJsonParser;
import com.abhay.sensitive_data_detector.service.FindingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/scan")
public class ScanController {

    private final WiresharkJsonParser parser;
    private final DetectionService detector;
    private final FindingService findingService;

    public ScanController(
            WiresharkJsonParser parser,
            DetectionService detector,
            FindingService findingService) {

        this.parser = parser;
        this.detector = detector;
        this.findingService = findingService;
    }

    // Existing endpoint
    @PostMapping
    public List<Finding> scan() throws Exception {

        List<Finding> allFindings = new ArrayList<>();

        try (InputStream in =
                     Files.newInputStream(Path.of("evidence/capture.json"))) {

            List<CapturedRequest> requests = parser.parse(in);

            for (CapturedRequest request : requests) {
                allFindings.addAll(detector.detect(request));
            }
        }

        findingService.saveFindings(allFindings);

        return allFindings;
    }


    // NEW: Upload capture.json from dashboard
    @PostMapping("/file")
    public List<Finding> scanUploadedFile(
            @RequestParam("file") MultipartFile file) throws Exception {

        if (file.isEmpty()) {
            throw new IllegalArgumentException("Please upload a JSON file.");
        }

        List<Finding> allFindings = new ArrayList<>();

        try (InputStream in = file.getInputStream()) {

            List<CapturedRequest> requests = parser.parse(in);

            for (CapturedRequest request : requests) {
                allFindings.addAll(detector.detect(request));
            }
        }

        findingService.saveFindings(allFindings);

        return allFindings;
    }

    @PostMapping("/pdf")
    public ResponseEntity<?> scanPdf(
            @RequestParam("file") MultipartFile file) throws IOException {

        if (file.isEmpty()
                || !file.getOriginalFilename().toLowerCase().endsWith(".pdf")) {
            return ResponseEntity.badRequest()
                    .body("Please upload a PDF file.");
        }

        String text = PdfTextExtractor.extractText(file);
        List<Finding> findings = DetectionService.detectText(text);
        findingService.saveFindings(findings);

        return ResponseEntity.ok(findings);
    }
}