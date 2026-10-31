package com.abhay.sensitive_data_detector.parser;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class WiresharkJsonParserTest {

    @Test
    void parsesRealCapture() throws Exception {
        WiresharkJsonParser parser = new WiresharkJsonParser();

        List<CapturedRequest> requests;
        try (InputStream in = Files.newInputStream(Path.of("evidence/capture.json"))) {
            requests = parser.parse(in);
        }

        System.out.println("Requests found: " + requests.size());
        for (CapturedRequest r : requests) {
            System.out.println("---- frame " + r.frameNumber() + " | " + r.method() + " " + r.uri()
                    + " | " + r.srcIp() + " -> " + r.dstIp() + ":" + r.dstPort()
                    + " | encrypted=" + r.encrypted());
            System.out.println(r.rawText());
        }

        assertFalse(requests.isEmpty());
        assertTrue(requests.stream().anyMatch(r -> r.rawText().contains("FAKE-API-KEY")));
        assertTrue(requests.stream().anyMatch(r -> r.rawText().contains("FakePass@123")));
        assertTrue(requests.stream().noneMatch(CapturedRequest::encrypted));
    }
}
