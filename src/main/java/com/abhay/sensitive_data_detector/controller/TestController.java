package com.abhay.sensitive_data_detector.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import java.util.Map;


@RestController
@RequestMapping("/api/test")
public class TestController {

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody Map<String, String> body) {
        return Map.of("status", "login request received");
    }

    @PostMapping(value = "/form", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, String> form(@RequestParam Map<String, String> params) {
        return Map.of("status", "form request received");
    }

    @GetMapping("/data")
    public Map<String, String> data(@RequestParam Map<String, String> params,
                                    @RequestHeader(value = "Authorization", required = false) String auth) {
        return Map.of("status", "data request received");
    }
}