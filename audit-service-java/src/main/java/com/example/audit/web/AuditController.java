package com.example.audit.web;

import com.example.audit.model.AuditRecord;
import com.example.audit.service.AuditService;
import com.example.audit.service.AuditService.VerificationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/audit")
public class AuditController {

    private final AuditService svc;

    @Autowired
    public AuditController(AuditService svc) { this.svc = svc; }

    @PostMapping("/events")
    public ResponseEntity<AuditRecord> create(@RequestBody Map<String, Object> body) {
        String eventType = (String) body.get("eventType");
        String actorId = (String) body.get("actorId");
        String resourceType = (String) body.get("resourceType");
        String resourceId = (String) body.get("resourceId");
        Map<String, Object> payload = (Map<String, Object>) body.get("payload");
        String tsStr = (String) body.get("timestamp");
        Instant ts = tsStr == null ? null : Instant.parse(tsStr);
        if (eventType == null || actorId == null || resourceType == null || resourceId == null) {
            return ResponseEntity.badRequest().build();
        }
        AuditRecord rec = svc.append(eventType, actorId, resourceType, resourceId, payload, ts);
        return ResponseEntity.status(201).body(rec);
    }

    @GetMapping("/events")
    public ResponseEntity<Page<AuditRecord>> query(@RequestParam Optional<String> actorId,
                                                   @RequestParam Optional<String> resourceType,
                                                   @RequestParam Optional<String> resourceId,
                                                   @RequestParam Optional<String> eventType,
                                                   @RequestParam Optional<String> from,
                                                   @RequestParam Optional<String> to,
                                                   @RequestParam(defaultValue = "1") int page,
                                                   @RequestParam(defaultValue = "50") int limit) {
        Page<AuditRecord> p = svc.query(actorId, resourceType, resourceId, eventType, from, to, page, limit);
        return ResponseEntity.ok(p);
    }

    @GetMapping("/verify")
    public ResponseEntity<VerificationResult> verify() {
        VerificationResult r = svc.verifyChain();
        return ResponseEntity.ok(r);
    }
}
