package com.abhay.sensitive_data_detector.detection;


public record Finding(
        String type,
        String severity,
        String maskedValue,
        int frameNumber,
        String method,
        String uri
) {
}
