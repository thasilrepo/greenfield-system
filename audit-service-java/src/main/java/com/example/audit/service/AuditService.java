package com.example.audit.service;

import com.example.audit.model.AuditRecord;
import com.example.audit.repo.AuditRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import jakarta.persistence.criteria.Predicate;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class AuditService {
    private static final String GENESIS = "0".repeat(64);
    private final AuditRecordRepository repo;
    private final ObjectMapper mapper;

    public AuditService(AuditRecordRepository repo) {
        this.repo = repo;
        this.mapper = new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public AuditRecord append(String eventType, String actorId, String resourceType, String resourceId, Map<String, Object> payload, Instant timestamp) {
        Instant ts = Optional.ofNullable(timestamp).orElse(Instant.now());
        try {
            // stable serialization of content
            Map<String, Object> content = Map.of(
                    "eventType", eventType,
                    "actorId", actorId,
                    "resourceType", resourceType,
                    "resourceId", resourceId,
                    "payload", payload,
                    "timestamp", ts.toString()
            );
            String contentJson = mapper.writeValueAsString(content);
            String contentHash = sha256(contentJson);
            String prevHash = Optional.ofNullable(repo.findTopByOrderByIdDesc()).map(AuditRecord::getContentHash).orElse(GENESIS);
            AuditRecord rec = new AuditRecord(eventType, actorId, resourceType, resourceId, payload == null ? null : mapper.writeValueAsString(payload), ts, contentHash, prevHash);
            return repo.save(rec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Page<AuditRecord> query(Optional<String> actorId, Optional<String> resourceType, Optional<String> resourceId, Optional<String> eventType, Optional<String> from, Optional<String> to, int page, int limit) {
        Specification<AuditRecord> spec = (root, cq, cb) -> {
            List<Predicate> preds = new ArrayList<>();
            actorId.ifPresent(a -> preds.add(cb.equal(root.get("actorId"), a)));
            resourceType.ifPresent(r -> preds.add(cb.equal(root.get("resourceType"), r)));
            resourceId.ifPresent(rid -> preds.add(cb.equal(root.get("resourceId"), rid)));
            eventType.ifPresent(e -> preds.add(cb.equal(root.get("eventType"), e)));
            from.ifPresent(f -> preds.add(cb.greaterThanOrEqualTo(root.get("timestamp"), Instant.parse(f))));
            to.ifPresent(t -> preds.add(cb.lessThanOrEqualTo(root.get("timestamp"), Instant.parse(t))));
            return cb.and(preds.toArray(new Predicate[0]));
        };
        return repo.findAll(spec, PageRequest.of(Math.max(0, page - 1), Math.max(1, Math.min(100, limit)), Sort.by("id")));
    }

    public VerificationResult verifyChain() {
        List<AuditRecord> all = repo.findAll(Sort.by(Sort.Direction.ASC, "id"));
        String expectedPrev = GENESIS;
        for (int i = 0; i < all.size(); i++) {
            AuditRecord r = all.get(i);
            try {
                Map<String, Object> content = Map.of(
                        "eventType", r.getEventType(),
                        "actorId", r.getActorId(),
                        "resourceType", r.getResourceType(),
                        "resourceId", r.getResourceId(),
                        "payload", r.getPayload() == null ? null : mapper.readValue(r.getPayload(), Map.class),
                        "timestamp", r.getTimestamp().toString()
                );
                String computed = sha256(mapper.writeValueAsString(content));
                if (!computed.equals(r.getContentHash())) {
                    return new VerificationResult(false, i, "content_hash_mismatch", r.getId());
                }
                if (!r.getPrevHash().equals(expectedPrev)) {
                    return new VerificationResult(false, i, "prev_hash_mismatch", r.getId());
                }
                expectedPrev = r.getContentHash();
            } catch (Exception e) {
                return new VerificationResult(false, i, "exception", r.getId());
            }
        }
        return new VerificationResult(true, -1, null, null);
    }

    public static class VerificationResult {
        public final boolean intact;
        public final int firstBrokenIndex;
        public final String reason;
        public final Long recordId;

        public VerificationResult(boolean intact, int firstBrokenIndex, String reason, Long recordId) {
            this.intact = intact;
            this.firstBrokenIndex = firstBrokenIndex;
            this.reason = reason;
            this.recordId = recordId;
        }
    }
}
