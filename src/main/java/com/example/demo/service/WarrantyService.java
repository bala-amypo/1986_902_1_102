package com.example.demo.service;

import com.example.demo.entity.Warranty;
import java.util.List;

public interface WarrantyService {
    Warranty registerWarranty(Long userId, Long productId, Warranty warranty);
    List<Warranty> getUserWarranties(Long userId);
    Warranty getWarranty(Long warrantyId);
}