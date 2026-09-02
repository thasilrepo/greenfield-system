package com.example.audit.service;

import com.example.audit.model.AuditRecord;
import com.example.audit.model.RedactionRecord;
import com.example.audit.repo.AuditRecordRepository;
import com.example.audit.repo.RedactionRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.env.Environment;
import org.springframework.data.domain.Sort;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class AuditServiceUnitTest {

    private AuditRecordRepository repo;
    private RedactionRecordRepository redactionRepo;
    private Environment env;
    private AuditService svc;

    @BeforeEach
    void setup() {
        repo = mock(AuditRecordRepository.class);
        redactionRepo = mock(RedactionRecordRepository.class);
        env = mock(Environment.class);
        when(env.getProperty("audit.master-key")).thenReturn(null);
        svc = new AuditService(repo, redactionRepo, env);
    }

    private static String sha256Hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @Test
    void appendCreatesRecordWithGenesisPrev() throws Exception {
        when(repo.findTopByOrderByIdDesc()).thenReturn(null);
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Map<String,Object> payload = new HashMap<>();
        payload.put("a", "b");
        AuditRecord out = svc.append("EV", "actor", "rtype", "rid", payload, null);
        assertNotNull(out);
        assertEquals(64, out.getContentHash().length());
        assertEquals(out.getPrevHash(), "0".repeat(64));
        verify(repo).save(any());
    }

    @Test
    void redactRemovesEncryptedKeyAndSavesRedaction() throws Exception {
        AuditRecord existing = new AuditRecord("E","A","T","R","enc", "ph", "2026-01-01T00:00:00Z","ch","prev","ek");
        existing.setId(5L);
        when(repo.findById(5L)).thenReturn(Optional.of(existing));
        when(redactionRepo.save(any())).thenAnswer(inv -> {
            RedactionRecord r = inv.getArgument(0);
            r.setId(11L);
            return r;
        });
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        RedactionRecord rr = svc.redactRecord(5L, "red", List.of("payload.ssn"));
        assertNotNull(rr);
        ArgumentCaptor<AuditRecord> ac = ArgumentCaptor.forClass(AuditRecord.class);
        verify(repo, atLeastOnce()).save(ac.capture());
        List<AuditRecord> saved = ac.getAllValues();
        boolean cleared = saved.stream().anyMatch(r -> r.getEncryptedKey() == null);
        assertTrue(cleared, "encryptedKey should be cleared during redact");
    }

    @Test
    void eraseRemovesEncryptedKeyAndAppendsEvent() throws Exception {
        AuditRecord existing = new AuditRecord("E","A","T","R","enc", "ph", "2026-01-01T00:00:00Z","ch","prev","ek");
        existing.setId(6L);
        when(repo.findById(6L)).thenReturn(Optional.of(existing));
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AuditRecord updated = svc.eraseRecord(6L, "eraser");
        assertNotNull(updated);
        assertNull(updated.getEncryptedKey());
        verify(repo, atLeastOnce()).save(any());
    }

    @Test
    void archiveOlderThanDaysMarksAndCounts() {
        AuditRecord old = new AuditRecord("E","A","T","R",null, "ph", Instant.now().minusSeconds(60L*60*24*40).toString(),"ch","prev",null);
        old.setId(1L);
        AuditRecord recent = new AuditRecord("E","A","T","R",null, "ph", Instant.now().toString(),"ch","prev",null);
        recent.setId(2L);
        when(repo.findAll()).thenReturn(List.of(old, recent));
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        int cnt = svc.archiveOlderThanDays(30);
        assertEquals(1, cnt);
    }

    @Test
    void applyRedactionViewReturnsOriginalWhenNoKeyOrPayload() {
        AuditRecord r = new AuditRecord("E","A","T","R",null, "ph", "ts","ch","prev",null);
        AuditRecord out = svc.applyRedactionView(r);
        assertSame(r, out);
    }

    @Test
    void applyRedactionViewDecryptsAndRedactsFields() throws Exception {
        when(repo.findTopByOrderByIdDesc()).thenReturn(null);
        when(repo.save(any())).thenAnswer(inv -> {
            AuditRecord ar = inv.getArgument(0);
            // simulate DB-generated ID
            if (ar.getId() == null) ar.setId(100L);
            return ar;
        });
        // create a record with nested payload
        Map<String,Object> payload = new HashMap<>();
        payload.put("user", Map.of("ssn","111-22-3333","name","Alice"));
        AuditRecord saved = svc.append("EV","actor","type","rid", payload, null);
        assertNotNull(saved.getEncryptedKey());
        assertNotNull(saved.getPayloadEncrypted());
        // create redaction metadata that removes user.ssn
        RedactionRecord rr = new RedactionRecord();
        rr.setId(55L);
        rr.setTargetRecordId(saved.getId());
        rr.setFieldsJson("[\"user.ssn\"]");
        when(redactionRepo.findByTargetRecordIdOrderByIdDesc(saved.getId())).thenReturn(List.of(rr));

        AuditRecord view = svc.applyRedactionView(saved);
        assertNotNull(view);
        // payloadEncrypted field in view will contain plaintext JSON
        String plain = view.getPayloadEncrypted();
        assertNotNull(plain);
        assertFalse(plain.contains("111-22-3333"));
        assertTrue(plain.contains("Alice"));
    }

    @Test
    void applyRedactionViewDecryptsAndReturnsPlaintextWhenNoRedactions() throws Exception {
        when(repo.findTopByOrderByIdDesc()).thenReturn(null);
        when(repo.save(any())).thenAnswer(inv -> {
            AuditRecord ar = inv.getArgument(0);
            if (ar.getId() == null) ar.setId(200L);
            return ar;
        });
        Map<String,Object> payload = new HashMap<>();
        payload.put("user", Map.of("ssn","222-33-4444","name","Bob"));
        AuditRecord saved = svc.append("EVP","actor","type","rid", payload, null);
        assertNotNull(saved.getEncryptedKey());
        assertNotNull(saved.getPayloadEncrypted());
        // no redaction records
        when(redactionRepo.findByTargetRecordIdOrderByIdDesc(saved.getId())).thenReturn(Collections.emptyList());

        AuditRecord view = svc.applyRedactionView(saved);
        assertNotNull(view);
        // should be a copy with plaintext payload in payloadEncrypted
        assertEquals(saved.getId(), view.getId());
        String plain = view.getPayloadEncrypted();
        assertNotNull(plain);
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        Map<?,?> parsed = mapper.readValue(plain, Map.class);
        Map<?,?> user = (Map<?,?>) parsed.get("user");
        assertEquals("Bob", user.get("name"));
        assertEquals("222-33-4444", user.get("ssn"));
    }

    @Test
    void exportBundleRequiresParamAndReturnsBundle() {
        AuditRecord r1 = new AuditRecord("E","actorX","type","rid","enc","ph","ts","ch","prev","ek");
        r1.setId(10L);
        when(repo.findAll(any(Sort.class))).thenReturn(List.of(r1));
        Map<String,Object> b = svc.exportBundle(Optional.of("actorX"), Optional.empty());
        assertNotNull(b);
        assertTrue(b.containsKey("records"));

        assertThrows(IllegalArgumentException.class, () -> svc.exportBundle(Optional.empty(), Optional.empty()));
    }

    @Test
    void verifyChainDetectsConsistentChain() throws Exception {
        // build two records with consistent hashes
        // build content and compute hash similarly to service
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

        Map<String,Object> c1 = new LinkedHashMap<>();
        c1.put("eventType", "A");
        c1.put("actorId", "x");
        c1.put("resourceType", "t");
        c1.put("resourceId", "r");
        c1.put("payload", "ph1");
        c1.put("timestamp", "ts1");
        String ch1 = sha256Hex(mapper.writeValueAsString(c1));

        Map<String,Object> c2 = new LinkedHashMap<>();
        c2.put("eventType", "B");
        c2.put("actorId", "y");
        c2.put("resourceType", "t");
        c2.put("resourceId", "r");
        c2.put("payload", "ph2");
        c2.put("timestamp", "ts2");
        String ch2 = sha256Hex(mapper.writeValueAsString(c2));

        AuditRecord r1 = new AuditRecord("A","x","t","r",null,"ph1","ts1",ch1,"0".repeat(64),null);
        r1.setId(1L);
        AuditRecord r2 = new AuditRecord("B","y","t","r",null,"ph2","ts2",ch2,ch1,null);
        r2.setId(2L);

        when(repo.findAll(any(Sort.class))).thenReturn(List.of(r1, r2));
        AuditService.VerificationResult vr = svc.verifyChain();
        assertTrue(vr.intact);
    }

    @Test
    void verifyChainDetectsContentHashMismatch() throws Exception {
        AuditRecord r = new AuditRecord("A","x","t","r",null,"ph","ts","badch","0".repeat(64),null);
        r.setId(2L);
        when(repo.findAll(any(Sort.class))).thenReturn(List.of(r));
        AuditService.VerificationResult vr = svc.verifyChain();
        assertFalse(vr.intact);
        assertEquals("content_hash_mismatch", vr.reason);
        assertEquals(0, vr.firstBrokenIndex);
        assertEquals(r.getId(), vr.recordId);
    }

    @Test
    void verifyChainDetectsPrevHashMismatch() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        Map<String,Object> c1 = new LinkedHashMap<>();
        c1.put("eventType", "A");
        c1.put("actorId", "x");
        c1.put("resourceType", "t");
        c1.put("resourceId", "r");
        c1.put("payload", "ph1");
        c1.put("timestamp", "ts1");
        String ch1 = sha256Hex(mapper.writeValueAsString(c1));
        AuditRecord r1 = new AuditRecord("A","x","t","r",null,"ph1","ts1",ch1,"0".repeat(64),null);
        r1.setId(1L);
        // r2 with wrong prevHash but correct contentHash
        Map<String,Object> c2 = new LinkedHashMap<>();
        c2.put("eventType", "B");
        c2.put("actorId", "y");
        c2.put("resourceType", "t");
        c2.put("resourceId", "r");
        c2.put("payload", "ph2");
        c2.put("timestamp", "ts2");
        String ch2 = sha256Hex(mapper.writeValueAsString(c2));
        AuditRecord r2 = new AuditRecord("B","y","t","r",null,"ph2","ts2",ch2,"wrongprev",null);
        r2.setId(2L);
        when(repo.findAll(any(Sort.class))).thenReturn(List.of(r1, r2));
        AuditService.VerificationResult vr = svc.verifyChain();
        assertFalse(vr.intact);
        assertEquals("prev_hash_mismatch", vr.reason);
        assertEquals(1, vr.firstBrokenIndex);
        assertEquals(r2.getId(), vr.recordId);
    }

    @Test
    void redactThrowsWhenRecordMissing() {
        when(repo.findById(999L)).thenReturn(Optional.empty());
        assertThrows(RuntimeException.class, () -> svc.redactRecord(999L, "r", List.of("a")));
    }

    @Test
    void eraseThrowsWhenRecordMissing() {
        when(repo.findById(888L)).thenReturn(Optional.empty());
        assertThrows(RuntimeException.class, () -> svc.eraseRecord(888L, "e"));
    }

    @Test
    void listRedactionsDelegatesToRepo() {
        RedactionRecord rr = new RedactionRecord(); rr.setId(1L); rr.setTargetRecordId(10L);
        when(redactionRepo.findByTargetRecordIdOrderByIdDesc(10L)).thenReturn(List.of(rr));
        List<RedactionRecord> got = svc.listRedactionsForRecord(10L);
        assertEquals(1, got.size());
    }
}

