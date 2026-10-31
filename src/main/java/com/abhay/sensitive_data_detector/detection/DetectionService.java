package com.abhay.sensitive_data_detector.detection;

import com.abhay.sensitive_data_detector.parser.CapturedRequest;
import com.abhay.sensitive_data_detector.parser.PdfTextExtractor;
import org.springframework.stereotype.Service;
import com.abhay.sensitive_data_detector.entity.FindingEntity;
import com.abhay.sensitive_data_detector.repository.FindingRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DetectionService {


        private final FindingRepository repository;

        public DetectionService(FindingRepository repository) {
            this.repository = repository;
        }

    private static final Pattern API_KEY =
            Pattern.compile("(?i)(api[_\\s-]?key\\s*[=:]\\s*[\"']?)([^\\s&\"']+)");

    private static final Pattern PASSWORD =
            Pattern.compile("(?i)(password\\s*[=:]\\s*[\"']?)([^\\s&\"']+)");

    private static final Pattern BEARER_TOKEN =
            Pattern.compile("(?i)(Bearer\\s+)([^\\s]+)");

    private static final Pattern EMAIL =
            Pattern.compile("(?i)([a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,})");

    public List<Finding> detect(CapturedRequest request) {

        List<Finding> findings = new ArrayList<>();

        detectPattern(request, API_KEY, "API_KEY", "CRITICAL", findings);
        detectPattern(request, PASSWORD, "PASSWORD", "CRITICAL", findings);
        detectPattern(request, BEARER_TOKEN, "BEARER_TOKEN", "HIGH", findings);
        detectEmail(request, EMAIL, "EMAIL", "MEDIUM", findings);

        return findings;
    }

    private void detectPattern(
            CapturedRequest request,
            Pattern pattern,
            String type,
            String severity,
            List<Finding> findings) {

        Matcher matcher = pattern.matcher(request.rawText());

        while (matcher.find()) {

            String value = matcher.group(2);

            findings.add(new Finding(
                    type,
                    severity,
                    mask(value),
                    request.frameNumber(),
                    request.method(),
                    sanitizeUri(request.uri())
            ));
        }
    }

    private static String mask(String value) {

        if (value.length() <= 4) {
            return "****";
        }

        return value.substring(0, 4)
                + "********"
                + value.substring(value.length() - 4);
    }

    private void detectEmail(
            CapturedRequest request,
            Pattern pattern,
            String type,
            String severity,
            List<Finding> findings) {

        Matcher matcher = pattern.matcher(request.rawText());

        while (matcher.find()) {

            String value = matcher.group(1);

            findings.add(new Finding(
                    type,
                    severity,
                    mask(value),
                    request.frameNumber(),
                    request.method(),
                    sanitizeUri(request.uri())
            ));
        }
    }

    private String sanitizeUri(String uri) {
        if (uri == null || uri.isBlank()) {
            return uri;
        }

        String sanitized = maskQueryParameter(uri, "api[_-]?key");
        sanitized = maskQueryParameter(sanitized, "email");

        return sanitized;
    }

    private String maskQueryParameter(String uri, String parameter) {
        Pattern pattern = Pattern.compile(
                "(?i)(" + parameter + "=)([^&\\s]+)"
        );

        Matcher matcher = pattern.matcher(uri);
        StringBuffer result = new StringBuffer();

        while (matcher.find()) {
            String maskedValue = mask(matcher.group(2));

            matcher.appendReplacement(
                    result,
                    Matcher.quoteReplacement(matcher.group(1) + maskedValue)
            );
        }

        matcher.appendTail(result);
        return result.toString();
    }

    public static List<Finding> detectText(String text) {

        List<Finding> findings = new ArrayList<>();

        if (text == null || text.isBlank()) {
            return findings;
        }

        detectTextPattern(text, API_KEY, "API_KEY", "CRITICAL", findings);
        detectTextPattern(text, PASSWORD, "PASSWORD", "CRITICAL", findings);
        detectTextPattern(text, BEARER_TOKEN, "BEARER_TOKEN", "HIGH", findings);
        detectTextEmail(text, EMAIL, "EMAIL", "MEDIUM", findings);



        return findings.stream()
                .distinct()
                .toList();
    }

    private static void detectTextPattern(
            String text,
            Pattern pattern,
            String type,
            String severity,
            List<Finding> findings) {

        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            String value = matcher.group(2);

            findings.add(new Finding(
                    type,
                    severity,
                    mask(value),
                    0,
                    "PDF",
                    "PDF document"
            ));
        }
    }

    private static void detectTextEmail(
            String text,
            Pattern pattern,
            String type,
            String severity,
            List<Finding> findings) {

        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            String value = matcher.group(1);

            findings.add(new Finding(
                    type,
                    severity,
                    mask(value),
                    0,
                    "PDF",
                    "PDF document"
            ));
        }
    }

}

