package com.abhay.sensitive_data_detector.controller;



import com.abhay.sensitive_data_detector.service.FindingService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final FindingService findingService;

    public DashboardController(FindingService findingService) {
        this.findingService = findingService;
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {

        model.addAttribute(
                "findings",
                findingService.getAllFindings()
        );

        return "dashboard";
    }
}
