package com.example.demo.service.impl;

import com.example.demo.entity.AlertLog;
import com.example.demo.entity.Warranty;
import com.example.demo.exception.ResourceNotFoundException;
import com.example.demo.repository.AlertLogRepository;
import com.example.demo.repository.WarrantyRepository;
import com.example.demo.service.AlertLogService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AlertLogServiceImpl implements AlertLogService {

    private final AlertLogRepository logRepository;
    private final WarrantyRepository warrantyRepository;

    public AlertLogServiceImpl(AlertLogRepository logRepository, 
                               WarrantyRepository warrantyRepository) {
        this.logRepository = logRepository;
        this.warrantyRepository = warrantyRepository;
    }

    @Override
    public AlertLog addLog(Long warrantyId, String message) {
        Warranty warranty = warrantyRepository.findById(warrantyId)
                .orElseThrow(() -> new ResourceNotFoundException("Warranty not found"));

        AlertLog log = AlertLog.builder()
                .warranty(warranty)
                .message(message)
                .build();
        
        // Entity @PrePersist handles timestamp
        return logRepository.save(log);
    }

    @Override
    public List<AlertLog> getLogs(Long warrantyId) {
        if (warrantyRepository.findById(warrantyId).isEmpty()) {
            throw new ResourceNotFoundException("Warranty not found");
        }
        return logRepository.findByWarrantyId(warrantyId);
    }
}