package com.example.audit.web;

import com.example.audit.model.AuditRecord;
import com.example.audit.service.AuditService;
import com.example.audit.service.AuditService.VerificationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.List;

@RestController
@RequestMapping("/audit")
public class AuditController {

    private final AuditService svc;
    private final ObjectMapper mapper = new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    @Autowired
    public AuditController(AuditService svc) { this.svc = svc; }

    private Map<String,Object> safeRecordView(AuditRecord r, boolean includePayload) {
        java.util.Map<String,Object> m = new java.util.HashMap<>();
        m.put("id", r.getId());
        m.put("eventType", r.getEventType());
        m.put("actorId", r.getActorId());
        m.put("resourceType", r.getResourceType());
        m.put("resourceId", r.getResourceId());
        m.put("payloadHash", r.getPayloadHash());
        m.put("payloadAvailable", r.getEncryptedKey() != null && r.getPayloadEncrypted() != null);
        m.put("timestamp", r.getTimestamp());
        m.put("contentHash", r.getContentHash());
        m.put("prevHash", r.getPrevHash());
        m.put("archived", Boolean.TRUE.equals(r.getArchived()));
        m.put("archivedAt", r.getArchivedAt());
        if (includePayload) {
            try {
                if (r.getPayloadEncrypted() == null) m.put("payload", null);
                else {
                    // payloadEncrypted may contain plaintext when produced by applyRedactionView
                    String s = r.getPayloadEncrypted();
                    try {
                        Object obj = mapper.readValue(s, Map.class);
                        m.put("payload", obj);
                    } catch (Exception ex) {
                        m.put("payload", s);
                    }
                }
            } catch (Exception ee) {
                m.put("payload", null);
            }
        }
        return m;
    }

    @PostMapping("/events")
    public ResponseEntity<?> create(@RequestBody Map<String, Object> body) {
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
        return ResponseEntity.status(201).body(safeRecordView(rec, false));
    }

    @GetMapping("/events")
    public ResponseEntity<?> query(@RequestParam Optional<String> actorId,
                                                   @RequestParam Optional<String> resourceType,
                                                   @RequestParam Optional<String> resourceId,
                                                   @RequestParam Optional<String> eventType,
                                                   @RequestParam Optional<String> from,
                                                   @RequestParam Optional<String> to,
                                                   @RequestParam(defaultValue = "1") int page,
                                                   @RequestParam(defaultValue = "50") int limit,
                                                   @RequestParam(defaultValue = "false") boolean redacted) {
        org.springframework.data.domain.Page<AuditRecord> p = svc.query(actorId, resourceType, resourceId, eventType, from, to, page, limit);
        java.util.Map<String, Object> resp = new java.util.HashMap<>();
        resp.put("total", p.getTotalElements());
        resp.put("page", page);
        resp.put("limit", limit);
        List<Map<String,Object>> items = p.getContent().stream().map(r -> {
            AuditRecord view = redacted ? svc.applyRedactionView(r) : r;
            return safeRecordView(view, redacted);
        }).collect(java.util.stream.Collectors.toList());
        resp.put("items", items);
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
        return this.query(a, rt, rid, et, from, to, page, limit, false);
    }

    @PostMapping("/redact")
    public ResponseEntity<?> redact(@RequestBody Map<String,Object> body) {
        // body: { recordId: number, redactorId: string, fields: ["payload.ssn", ...] }
        Long recordId = body.get("recordId") instanceof Number ? ((Number)body.get("recordId")).longValue() : Long.valueOf(String.valueOf(body.get("recordId")));
        String redactorId = body.get("redactorId") == null ? null : String.valueOf(body.get("redactorId"));
        java.util.List<String> fields = body.get("fields") == null ? java.util.Collections.emptyList() : (java.util.List<String>) body.get("fields");
        try {
            Object saved = svc.redactRecord(recordId, redactorId, fields);
            return ResponseEntity.ok(saved);
        } catch (Exception e) {
            return ResponseEntity.status(400).body(java.util.Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/erase")
    public ResponseEntity<?> erase(@RequestBody Map<String,Object> body) {
        // body: { recordId: number, eraserId: string }
        Long recordId = body.get("recordId") instanceof Number ? ((Number)body.get("recordId")).longValue() : Long.valueOf(String.valueOf(body.get("recordId")));
        String eraserId = body.get("eraserId") == null ? null : String.valueOf(body.get("eraserId"));
        try {
            AuditRecord updated = svc.eraseRecord(recordId, eraserId);
            return ResponseEntity.ok(safeRecordView(updated, false));
        } catch (Exception e) {
            return ResponseEntity.status(400).body(java.util.Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/archive")
    public ResponseEntity<?> archive(@RequestParam(defaultValue = "30") long days) {
        int count = svc.archiveOlderThanDays(days);
        return ResponseEntity.ok(java.util.Map.of("archived", count));
    }

    @GetMapping("/export")
    public ResponseEntity<?> export(@RequestParam Optional<String> actorId,
                                    @RequestParam Optional<String> resourceId) {
        try {
            java.util.Map<String,Object> bundle = svc.exportBundle(actorId, resourceId);
            return ResponseEntity.ok(bundle);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<VerificationResult> verify() {
        VerificationResult r = svc.verifyChain();
        return ResponseEntity.ok(r);
    }
}
