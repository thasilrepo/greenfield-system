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
        if (eventType == null || actorId == null || resourceType == null || resourceId == null) {
            return ResponseEntity.badRequest().build();
        }
        AuditRecord rec = svc.append(eventType, actorId, resourceType, resourceId, payload, tsStr);
        return ResponseEntity.status(201).body(rec);
    }

    @GetMapping("/events")
    public ResponseEntity<?> query(@RequestParam Optional<String> actorId,
                                                   @RequestParam Optional<String> resourceType,
                                                   @RequestParam Optional<String> resourceId,
                                                   @RequestParam Optional<String> eventType,
                                                   @RequestParam Optional<String> from,
                                                   @RequestParam Optional<String> to,
                                                   @RequestParam(defaultValue = "1") int page,
                                                   @RequestParam(defaultValue = "50") int limit) {
        org.springframework.data.domain.Page<AuditRecord> p = svc.query(actorId, resourceType, resourceId, eventType, from, to, page, limit);
        java.util.Map<String, Object> resp = new java.util.HashMap<>();
        resp.put("total", p.getTotalElements());
        resp.put("page", page);
        resp.put("limit", limit);
        resp.put("items", p.getContent());
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/events/{filterField}")
    public ResponseEntity<?> queryByField(@PathVariable String filterField,
                                          @RequestParam(name = "value", required = true) String value,
                                          @RequestParam Optional<String> from,
                                          @RequestParam Optional<String> to,
                                          @RequestParam(defaultValue = "1") int page,
                                          @RequestParam(defaultValue = "50") int limit) {
        return handleFilter(filterField, value, from, to, page, limit);
    }

    @GetMapping("/events/{filterField}/{value}")
    public ResponseEntity<?> queryByFieldPath(@PathVariable String filterField,
                                              @PathVariable String value,
                                              @RequestParam Optional<String> from,
                                              @RequestParam Optional<String> to,
                                              @RequestParam(defaultValue = "1") int page,
                                              @RequestParam(defaultValue = "50") int limit) {
        return handleFilter(filterField, value, from, to, page, limit);
    }

    private ResponseEntity<?> handleFilter(String filterField, String value, Optional<String> from, Optional<String> to, int page, int limit) {
        // normalize and map to query optionals
        Optional<String> a = Optional.empty();
        Optional<String> rt = Optional.empty();
        Optional<String> rid = Optional.empty();
        Optional<String> et = Optional.empty();
        String f = filterField == null ? "" : filterField.toLowerCase();
        switch (f) {
            case "actorid": case "actor": case "actor_id":
                a = Optional.of(value);
                break;
            case "eventtype": case "event_type": case "event":
                et = Optional.of(value);
                break;
            case "resourcetype": case "resource_type": case "type":
                rt = Optional.of(value);
                break;
            case "resourceid": case "resource_id": case "id":
                rid = Optional.of(value);
                break;
            case "resource":
                if (value.contains(":")) {
                    String[] parts = value.split(":", 2);
                    rt = Optional.of(parts[0]);
                    rid = Optional.of(parts[1]);
                } else {
                    rt = Optional.of(value);
                }
                break;
            default:
                java.util.Map<String, Object> err = new java.util.HashMap<>();
                err.put("error", "unsupported filter field");
                err.put("supported", java.util.List.of("actorId","eventType","resourceType","resourceId","resource"));
                return ResponseEntity.badRequest().body(err);
        }
        return this.query(a, rt, rid, et, from, to, page, limit);
    }

    @GetMapping("/verify")
    public ResponseEntity<VerificationResult> verify() {
        VerificationResult r = svc.verifyChain();
        return ResponseEntity.ok(r);
    }
}
