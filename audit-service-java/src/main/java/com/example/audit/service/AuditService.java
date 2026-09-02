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
import java.util.LinkedHashMap;
import com.example.audit.model.RedactionRecord;
import com.example.audit.repo.RedactionRecordRepository;
import org.springframework.transaction.annotation.Transactional;
import java.util.stream.Collectors;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Collections;
import java.util.Base64;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.core.env.Environment;
import java.time.Duration;

@Service
public class AuditService {
    private static final String GENESIS = "0".repeat(64);
    private final AuditRecordRepository repo;
    private final RedactionRecordRepository redactionRepo;
    private final ObjectMapper mapper;

    public AuditService(AuditRecordRepository repo, RedactionRecordRepository redactionRepo, Environment env) {
        this.repo = repo;
        this.redactionRepo = redactionRepo;
        this.mapper = new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        this.masterKeyBytes = ensureMasterKeyBytes(env.getProperty("audit.master-key"));
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

    // encryption helpers
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final byte[] masterKeyBytes;
    private final SecureRandom secureRandom = new SecureRandom();

    private byte[] ensureMasterKeyBytes(String base64) {
        try {
            if (base64 != null && !base64.isBlank()) return Base64.getDecoder().decode(base64);
        } catch (Exception e) { /* ignore */ }
        // generate transient master key (WARNING: ephemeral, will not survive restart)
        byte[] k = new byte[32];
        secureRandom.nextBytes(k);
        return k;
    }

    private String encryptWithKey(byte[] key, byte[] plain) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH]; secureRandom.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        c.init(Cipher.ENCRYPT_MODE, spec, gcm);
        byte[] ct = c.doFinal(plain);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    private byte[] decryptWithKey(byte[] key, String base64) throws Exception {
        byte[] in = Base64.getDecoder().decode(base64);
        byte[] iv = Arrays.copyOfRange(in, 0, GCM_IV_LENGTH);
        byte[] ct = Arrays.copyOfRange(in, GCM_IV_LENGTH, in.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        c.init(Cipher.DECRYPT_MODE, spec, gcm);
        return c.doFinal(ct);
    }

    private static class EncResult { String encryptedPayload; String encryptedKey; String payloadHash; }

    private EncResult encryptPayloadAndKey(String plaintext) throws Exception {
        EncResult r = new EncResult();
        byte[] dataKey = new byte[32]; secureRandom.nextBytes(dataKey);
        // encrypt payload with dataKey
        r.encryptedPayload = encryptWithKey(dataKey, plaintext.getBytes(StandardCharsets.UTF_8));
        // encrypt dataKey with masterKey
        r.encryptedKey = encryptWithKey(masterKeyBytes, dataKey);
        r.payloadHash = sha256(plaintext);
        return r;
    }

    private byte[] decryptDataKey(String encryptedKeyBase64) throws Exception {
        if (encryptedKeyBase64 == null) return null;
        return decryptWithKey(masterKeyBytes, encryptedKeyBase64);
    }

    private String decryptPayloadWithDataKey(String encryptedPayloadBase64, byte[] dataKey) throws Exception {
        if (encryptedPayloadBase64 == null || dataKey == null) return null;
        byte[] p = decryptWithKey(dataKey, encryptedPayloadBase64);
        return new String(p, StandardCharsets.UTF_8);
    }

    public AuditRecord append(String eventType, String actorId, String resourceType, String resourceId, Map<String, Object> payload, String timestamp) {
        String ts = Optional.ofNullable(timestamp).orElse(Instant.now().toString());
        try {
            String payloadHash = null;
            String payloadEncrypted = null;
            String encryptedKey = null;
            if (payload != null) {
                String payloadJson = mapper.writeValueAsString(payload);
                EncResult er = encryptPayloadAndKey(payloadJson);
                payloadHash = er.payloadHash;
                payloadEncrypted = er.encryptedPayload;
                encryptedKey = er.encryptedKey;
            }
            // build content using payloadHash (so verification doesn't need plaintext)
            Map<String, Object> content = new LinkedHashMap<>();
            content.put("eventType", eventType);
            content.put("actorId", actorId);
            content.put("resourceType", resourceType);
            content.put("resourceId", resourceId);
            content.put("payload", payloadHash);
            content.put("timestamp", ts);
            String contentJson = mapper.writeValueAsString(content);
            String contentHash = sha256(contentJson);
            String prevHash = Optional.ofNullable(repo.findTopByOrderByIdDesc()).map(AuditRecord::getContentHash).orElse(GENESIS);
            AuditRecord rec = new AuditRecord(eventType, actorId, resourceType, resourceId, payloadEncrypted, payloadHash, ts, contentHash, prevHash, encryptedKey);
            return repo.save(rec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    @Transactional
    public RedactionRecord redactRecord(Long recordId, String redactorId, List<String> fields) {
        try {
            AuditRecord target = repo.findById(recordId).orElseThrow(() -> new IllegalArgumentException("record not found"));
            String origHash = target.getPayloadHash();
            RedactionRecord rr = new RedactionRecord();
            rr.setTargetRecordId(recordId);
            rr.setRedactorId(redactorId);
            rr.setFieldsJson(mapper.writeValueAsString(fields == null ? Collections.emptyList() : fields));
            rr.setOriginalPayloadHash(origHash);
            rr.setTimestamp(Instant.now().toString());
            RedactionRecord saved = redactionRepo.save(rr);
            // cryptographic erasure: delete the encryptedKey so payload cannot be decrypted
            target.setEncryptedKey(null);
            repo.save(target);
            // append an audit event describing the redaction
            Map<String,Object> payload = new HashMap<>();
            payload.put("targetRecordId", recordId);
            payload.put("fields", fields == null ? Collections.emptyList() : fields);
            payload.put("originalPayloadHash", origHash);
            this.append("REDACTION", redactorId != null ? redactorId : "system", "redaction", String.valueOf(recordId), payload, Instant.now().toString());
            return saved;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public List<RedactionRecord> listRedactionsForRecord(Long recordId) {
        return redactionRepo.findByTargetRecordIdOrderByIdDesc(recordId);
    }

    public int archiveOlderThanDays(long days) {
        Instant cutoff = Instant.now().minus(Duration.ofDays(Math.max(0, days)));
        List<AuditRecord> all = repo.findAll();
        int count = 0;
        for (AuditRecord r : all) {
            try {
                if (r.getTimestamp() == null) continue;
                Instant its = Instant.parse(r.getTimestamp());
                if (its.isBefore(cutoff) && !r.isArchived()) {
                    r.setArchived(true);
                    r.setArchivedAt(Instant.now().toString());
                    repo.save(r);
                    count++;
                }
            } catch (Exception e) {
                // skip parse errors
            }
        }
        return count;
    }

    public AuditRecord applyRedactionView(AuditRecord rec) {
        // decrypt payload (if possible), apply latest redaction fields, and return a copy with plaintext payload in 'payloadEncrypted' field replaced by plaintext for viewing purposes
        try {
            // decrypt data key
            if (rec.getEncryptedKey() == null || rec.getPayloadEncrypted() == null) return rec;
            byte[] dataKey = decryptDataKey(rec.getEncryptedKey());
            if (dataKey == null) return rec;
            String plain = decryptPayloadWithDataKey(rec.getPayloadEncrypted(), dataKey);
            List<RedactionRecord> rrs = redactionRepo.findByTargetRecordIdOrderByIdDesc(rec.getId());
            if (rrs != null && !rrs.isEmpty()) {
                RedactionRecord latest = rrs.get(0);
                List<String> paths = mapper.readValue(latest.getFieldsJson(), List.class);
                Map<String,Object> obj = mapper.readValue(plain, Map.class);
                for (String p : paths) {
                    String[] parts = p.split("\\.");
                    Map current = obj;
                    for (int i = 0; i < parts.length - 1; i++) {
                        Object next = current.get(parts[i]);
                        if (!(next instanceof Map)) { current = null; break; }
                        current = (Map) next;
                    }
                    if (current != null) current.remove(parts[parts.length-1]);
                }
                String redactedJson = mapper.writeValueAsString(obj);
                AuditRecord copy = new AuditRecord(rec.getEventType(), rec.getActorId(), rec.getResourceType(), rec.getResourceId(), redactedJson, rec.getPayloadHash(), rec.getTimestamp(), rec.getContentHash(), rec.getPrevHash(), rec.getEncryptedKey());
                copy.setId(rec.getId());
                return copy;
            } else {
                // no specific field-level redaction — return plaintext view
                AuditRecord copy = new AuditRecord(rec.getEventType(), rec.getActorId(), rec.getResourceType(), rec.getResourceId(), plain, rec.getPayloadHash(), rec.getTimestamp(), rec.getContentHash(), rec.getPrevHash(), rec.getEncryptedKey());
                copy.setId(rec.getId());
                return copy;
            }
        } catch (Exception e) {
            return rec;
        }
    }

    public Map<String,Object> exportBundle(Optional<String> actorId, Optional<String> resourceId) {
        List<AuditRecord> records;
        if (actorId.isPresent()) records = repo.findAll(org.springframework.data.domain.Sort.by(org.springframework.data.domain.Sort.Direction.ASC, "id")).stream().filter(r -> r.getActorId().equals(actorId.get())).collect(Collectors.toList());
        else if (resourceId.isPresent()) records = repo.findAll(org.springframework.data.domain.Sort.by(org.springframework.data.domain.Sort.Direction.ASC, "id")).stream().filter(r -> r.getResourceId().equals(resourceId.get())).collect(Collectors.toList());
        else throw new IllegalArgumentException("actorId or resourceId required");
        List<Map<String,Object>> recs = records.stream().map(r -> {
            Map<String,Object> m = new HashMap<>();
            m.put("id", r.getId());
            m.put("eventType", r.getEventType());
            m.put("actorId", r.getActorId());
            m.put("resourceType", r.getResourceType());
            m.put("resourceId", r.getResourceId());
            // include payloadHash and flag whether payload is available (encrypted key present)
            m.put("payloadHash", r.getPayloadHash());
            m.put("payloadAvailable", r.getEncryptedKey() != null && r.getPayloadEncrypted() != null);
            m.put("timestamp", r.getTimestamp());
            m.put("contentHash", r.getContentHash());
            m.put("prevHash", r.getPrevHash());
            m.put("archived", r.isArchived());
            m.put("archivedAt", r.getArchivedAt());
            return m;
        }).collect(Collectors.toList());
        Map<String,Object> bundle = new HashMap<>();
        bundle.put("exportedAt", Instant.now().toString());
        bundle.put("records", recs);
        // chain metadata
        List<Map<String,String>> chain = records.stream().map(r -> {
            Map<String,String> m = new HashMap<>(); m.put("id", String.valueOf(r.getId())); m.put("contentHash", r.getContentHash()); m.put("prevHash", r.getPrevHash()); return m;
        }).collect(Collectors.toList());
        bundle.put("chain", chain);
        return bundle;
    }

    public Page<AuditRecord> query(Optional<String> actorId, Optional<String> resourceType, Optional<String> resourceId, Optional<String> eventType, Optional<String> from, Optional<String> to, int page, int limit) {
        Specification<AuditRecord> spec = (root, cq, cb) -> {
            List<Predicate> preds = new ArrayList<>();
            actorId.ifPresent(a -> preds.add(cb.equal(root.get("actorId"), a)));
            resourceType.ifPresent(r -> preds.add(cb.equal(root.get("resourceType"), r)));
            resourceId.ifPresent(rid -> preds.add(cb.equal(root.get("resourceId"), rid)));
            eventType.ifPresent(e -> preds.add(cb.equal(root.get("eventType"), e)));
            // timestamp stored as ISO-8601 string -> lexicographic compare is valid for same format
            from.ifPresent(f -> preds.add(cb.greaterThanOrEqualTo(root.get("timestamp"), f)));
            to.ifPresent(t -> preds.add(cb.lessThanOrEqualTo(root.get("timestamp"), t)));
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
                // archived records are still part of the chain (soft-archived)
                Map<String, Object> content = new LinkedHashMap<>();
                // use payloadHash (sha256 of plaintext) in chain content so verification doesn't require plaintext
                content.put("eventType", r.getEventType());
                content.put("actorId", r.getActorId());
                content.put("resourceType", r.getResourceType());
                content.put("resourceId", r.getResourceId());
                content.put("payload", r.getPayloadHash());
                content.put("timestamp", r.getTimestamp());
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
