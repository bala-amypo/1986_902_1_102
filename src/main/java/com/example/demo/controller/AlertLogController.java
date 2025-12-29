package com.example.demo.controller;

import com.example.demo.entity.AlertLog;
import com.example.demo.service.AlertLogService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/logs")
public class AlertLogController {

    private final AlertLogService alertLogService;

    public AlertLogController(AlertLogService alertLogService) {
        this.alertLogService = alertLogService;
    }

    @PostMapping
    public ResponseEntity<AlertLog> addLog(@RequestParam Long warrantyId, 
                                           @RequestBody String message) {
        return ResponseEntity.ok(alertLogService.addLog(warrantyId, message));
    }

    @GetMapping
    public ResponseEntity<List<AlertLog>> getLogs(@RequestParam Long warrantyId) {
        return ResponseEntity.ok(alertLogService.getLogs(warrantyId));
    }
}