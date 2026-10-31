package com.abhay.sensitive_data_detector.parser;

public record CapturedRequest (
        int frameNumber,
        String time,
        String srcIp,
        String dstIp,
        String dstPort,
        boolean encrypted,
        String method,
        String uri,
        String rawText)
{
}
