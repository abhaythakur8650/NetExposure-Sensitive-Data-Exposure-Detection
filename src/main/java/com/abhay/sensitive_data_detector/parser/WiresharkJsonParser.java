package com.abhay.sensitive_data_detector.parser;

import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;

import java.util.List;

@Component
public class WiresharkJsonParser {

    private final ObjectMapper mapper = new ObjectMapper();

    public List<CapturedRequest> parse(InputStream in) {

        List<CapturedRequest> result = new ArrayList<>();

        JsonNode root = mapper.readTree(in);

        for (JsonNode packet : root) {

            JsonNode layers = packet
                    .path("_source")
                    .path("layers");

            JsonNode http = layers.path("http");

            // Only HTTP requests, skip responses and other packets
            if (http.isMissingNode() || !http.has("http.request")) {
                continue;
            }

            String protocols = layers
                    .path("frame")
                    .path("frame.protocols")
                    .asString("");

            boolean encrypted =
                    protocols.contains("tls") ||
                            protocols.contains("ssl");

            String hex = layers
                    .path("tcp")
                    .path("tcp.payload")
                    .asString("");

            String rawText =
                    hex.isEmpty() ? "" : hexToText(hex);

            /*
             * Wireshark stores the HTTP request information
             * inside a dynamic key such as:
             *
             * "GET /api/test/data HTTP/1.1\r\n"
             *
             * Inside that object we have:
             *
             * "http.request.method": "GET"
             * "http.request.uri": "/api/test/data"
             */

            String method = "";
            String uri = "";

            for (JsonNode requestNode : http) {

                if (requestNode.isObject()) {

                    String foundMethod = requestNode
                            .path("http.request.method")
                            .asString("");

                    String foundUri = requestNode
                            .path("http.request.uri")
                            .asString("");

                    if (!foundMethod.isEmpty()) {
                        method = foundMethod;
                    }

                    if (!foundUri.isEmpty()) {
                        uri = foundUri;
                    }

                    if (!method.isEmpty() || !uri.isEmpty()) {
                        break;
                    }
                }
            }

            System.out.println("METHOD = " + method);
            System.out.println("URI = " + uri);

            result.add(new CapturedRequest(
                    Integer.parseInt(
                            layers
                                    .path("frame")
                                    .path("frame.number")
                                    .asString("0")
                    ),

                    layers
                            .path("frame")
                            .path("frame.time")
                            .asString(""),

                    layers
                            .path("ip")
                            .path("ip.src")
                            .asString(""),

                    layers
                            .path("ip")
                            .path("ip.dst")
                            .asString(""),

                    layers
                            .path("tcp")
                            .path("tcp.dstport")
                            .asString(""),

                    encrypted,

                    method,

                    uri,

                    rawText
            ));
        }

        return result;
    }

    private static String hexToText(String hex) {

        String clean =
                hex.replace(":", "")
                        .replaceAll("\\s", "");

        return new String(
                HexFormat.of().parseHex(clean),
                StandardCharsets.UTF_8
        );
    }
}