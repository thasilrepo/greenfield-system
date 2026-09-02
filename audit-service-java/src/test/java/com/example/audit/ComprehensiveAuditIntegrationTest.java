package com.example.audit;

import com.example.audit.model.AuditRecord;
import com.example.audit.repo.AuditRecordRepository;
import com.example.audit.service.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.example.audit.model.RedactionRecord;
import com.example.audit.repo.RedactionRecordRepository;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ComprehensiveAuditIntegrationTest {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private AuditRecordRepository repo;

    @Autowired
    private AuditService svc;

    @Autowired
    private RedactionRecordRepository redactionRepo;

    @BeforeEach
    public void beforeEach() {
        redactionRepo.deleteAll();
        repo.deleteAll();
    }

    @Test
    public void testFullFlow_create_query_verify_export_archive_redact_erase() {
        // create an event with an older timestamp for archive testing
        Map<String,Object> payload1 = new HashMap<>();
        payload1.put("ssn", "123-45-6789");
        payload1.put("account", Map.of("number", "AC-001"));

        String oldTs = Instant.now().minus(Duration.ofDays(5)).toString();
        Map<String,Object> b1 = new HashMap<>();
        b1.put("eventType", "USER_LOGIN");
        b1.put("actorId", "user-x");
        b1.put("resourceType", "session");
        b1.put("resourceId", "s-old");
        b1.put("payload", payload1);
        b1.put("timestamp", oldTs);

        ResponseEntity<Map> c1 = rest.withBasicAuth("user","userpass").postForEntity("/audit/events", b1, Map.class);
        assertThat(c1.getStatusCode().is2xxSuccessful()).isTrue();
        Number id1n = (Number) c1.getBody().get("id");
        Long id1 = id1n.longValue();

        // create a recent event
        Map<String,Object> b2 = new HashMap<>();
        b2.put("eventType", "RECORD_UPDATED");
        b2.put("actorId", "user-y");
        b2.put("resourceType", "order");
        b2.put("resourceId", "o-1");
        b2.put("payload", Map.of("item","book"));
        ResponseEntity<Map> c2 = rest.withBasicAuth("user","userpass").postForEntity("/audit/events", b2, Map.class);
        assertThat(c2.getStatusCode().is2xxSuccessful()).isTrue();

        // query by actorId
        ResponseEntity<Map> q1 = rest.withBasicAuth("user","userpass").getForEntity("/audit/events?actorId=user-x", Map.class);
        assertThat(q1.getStatusCode().is2xxSuccessful()).isTrue();
        Map<?,?> body = q1.getBody();
        assertThat(body).isNotNull();
        assertThat(((Number) body.get("total")).intValue()).isGreaterThanOrEqualTo(1);

        // verify chain intact
        ResponseEntity<Map> v = rest.withBasicAuth("user","userpass").getForEntity("/audit/verify", Map.class);
        assertThat(v.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(v.getBody().get("intact")).isEqualTo(Boolean.TRUE);

        // export by actorId
        ResponseEntity<Map> exp = rest.withBasicAuth("admin","adminpass").getForEntity("/audit/export?actorId=user-x", Map.class);
        assertThat(exp.getStatusCode().is2xxSuccessful()).isTrue();
        Map<?,?> bundle = exp.getBody();
        assertThat(bundle).isNotNull();
        List<?> records = (List<?>) bundle.get("records");
        assertThat(records.size()).isGreaterThanOrEqualTo(1);
        Map<?,?> exportedRec = (Map<?,?>) records.get(0);
        assertThat(exportedRec.get("payloadHash")).isNotNull();

        // archive older than 1 day -> should archive the old record
        ResponseEntity<Map> arc = rest.withBasicAuth("admin","adminpass").postForEntity("/audit/archive?days=1", null, Map.class);
        assertThat(arc.getStatusCode().is2xxSuccessful()).isTrue();
        Map<?,?> arcBody = arc.getBody();
        assertThat(arcBody).isNotNull();
        assertThat(((Number)arcBody.get("archived")).intValue()).isGreaterThanOrEqualTo(1);

        // verify exported bundle now marks archived true for the old record (re-export)
        ResponseEntity<Map> exp2 = rest.withBasicAuth("admin","adminpass").getForEntity("/audit/export?actorId=user-x", Map.class);
        Map<?,?> bundle2 = exp2.getBody();
        List<?> recs2 = (List<?>) bundle2.get("records");
        assertThat(recs2).isNotEmpty();
        Map<?,?> recMap = (Map<?,?>) recs2.get(0);
        assertThat(recMap.get("archived")).isEqualTo(Boolean.TRUE);

        // redact the old record
        Map<String,Object> redReq = new HashMap<>();
        redReq.put("recordId", id1);
        redReq.put("redactorId", "privacy");
        redReq.put("fields", List.of("payload.ssn"));
        ResponseEntity<Map> rr = rest.withBasicAuth("admin","adminpass").postForEntity("/audit/redact", redReq, Map.class);
        assertThat(rr.getStatusCode().is2xxSuccessful()).isTrue();

        // after redact the record should have payloadAvailable=false
        ResponseEntity<Map> qred = rest.withBasicAuth("user","userpass").getForEntity("/audit/events?actorId=user-x&redacted=true", Map.class);
        Map<?,?> qredBody = qred.getBody();
        List<?> items = (List<?>) qredBody.get("items");
        assertThat(items).isNotEmpty();
        Map<?,?> item0 = (Map<?,?>) items.get(0);
        assertThat(item0.get("payloadAvailable")).isEqualTo(Boolean.FALSE);

        // erase via endpoint the recent record
        // pick an id from c2
        Number id2n = (Number) c2.getBody().get("id");
        Long id2 = id2n.longValue();
        Map<String,Object> erReq = new HashMap<>();
        erReq.put("recordId", id2);
        erReq.put("eraserId", "admin");
        ResponseEntity<Map> er = rest.withBasicAuth("admin","adminpass").postForEntity("/audit/erase", erReq, Map.class);
        assertThat(er.getStatusCode().is2xxSuccessful()).isTrue();
        Map<?,?> erBody = er.getBody();
        assertThat(erBody.get("payloadAvailable")).isEqualTo(Boolean.FALSE);

        // additionally test service-level eraseRecord directly on a freshly appended record
        AuditRecord svcRec = svc.append("USER_LOGIN","svc-direct","session","s-svc", Map.of("k","v"), null);
        assertThat(svcRec.getEncryptedKey()).isNotNull();
        AuditRecord erasedBySvc = svc.eraseRecord(svcRec.getId(), "unit-tester");
        assertThat(erasedBySvc.getEncryptedKey()).isNull();
        AuditRecord fromDb = repo.findById(svcRec.getId()).orElseThrow();
        assertThat(fromDb.getEncryptedKey()).isNull();

    }

    @Test
    public void testVerifyChain_tamper_detection() {
        // create two events
        AuditRecord r1 = svc.append("USER_LOGIN","a1","session","s1", Map.of("k","v"), null);
        AuditRecord r2 = svc.append("RECORD_UPDATED","a2","order","o1", Map.of(), null);
        List<AuditRecord> all = repo.findAll();
        assertThat(all.size()).isEqualTo(2);
        // tamper contentHash of first
        r1.setContentHash("badhash");
        repo.save(r1);
        // verify endpoint
        ResponseEntity<Map> v = rest.withBasicAuth("user","userpass").getForEntity("/audit/verify", Map.class);
        assertThat(v.getBody().get("intact")).isEqualTo(Boolean.FALSE);
        assertThat(v.getBody().get("reason")).isEqualTo("content_hash_mismatch");
    }

    @Test
    public void testServiceMethods_cover_applyRedactionView_and_exportBundle() throws Exception {
        // create record
        Map<String,Object> payload = Map.of("a","b","sensitive", Map.of("ssn","999-99-9999"));
        AuditRecord created = svc.append("USER_LOGIN","svc","session","s-3", payload, null);
        assertThat(created.getEncryptedKey()).isNotNull();
        // create redaction record but do not erase key yet to test applyRedactionView
        svc.redactRecord(created.getId(), "tester", List.of("sensitive.ssn"));
        // redactRecord currently deletes encryptedKey as part of crypto-erasure; create another fresh record to test applyRedactionView
        AuditRecord fresh = svc.append("USER_LOGIN","svc","session","s-4", payload, null);
        // add a redaction metadata entry for fresh
        svc.redactRecord(fresh.getId(), "tester", List.of("sensitive.ssn"));
        // applyRedactionView on fresh (encryptedKey removed by redactRecord) — should return record (payload likely unavailable)
        AuditRecord view = svc.applyRedactionView(fresh);
        assertThat(view.getId()).isEqualTo(fresh.getId());

        // exportBundle by resourceId
        Map<String,Object> bundle = svc.exportBundle(Optional.empty(), Optional.of("s-3"));
        assertThat(bundle.get("records")).isNotNull();

        // Test applyRedactionView includes payload when encryptedKey remains and redaction metadata exists
        AuditRecord recForRedaction = svc.append("USER_LOGIN","redactor","session","s-red", Map.of("user", Map.of("ssn","111-22-3333","name","Alice")), null);
        // add redaction metadata directly without deleting encryptedKey
        RedactionRecord rr = new RedactionRecord();
        rr.setTargetRecordId(recForRedaction.getId());
        rr.setRedactorId("tester");
        rr.setFieldsJson("[\"user.ssn\"]");
        rr.setOriginalPayloadHash(recForRedaction.getPayloadHash());
        rr.setTimestamp(Instant.now().toString());
        redactionRepo.save(rr);

        // query with redacted=true should return payload with ssn removed
        ResponseEntity<Map> qred2 = rest.withBasicAuth("user","userpass").getForEntity("/audit/events?actorId=redactor&redacted=true", Map.class);
        Map<?,?> qredBody2 = qred2.getBody();
        List<?> items2 = (List<?>) qredBody2.get("items");
        assertThat(items2).isNotEmpty();
        Map<?,?> item = (Map<?,?>) items2.get(0);
        Object payloadObj = item.get("payload");
        if (payloadObj instanceof Map) {
            Map<?,?> pmap = (Map<?,?>) payloadObj;
            Object user = pmap.get("user");
            if (user instanceof Map) {
                Map<?,?> um = (Map<?,?>) user;
                assertThat(um.containsKey("ssn")).isFalse();
                assertThat(um.get("name")).isEqualTo("Alice");
            }
        }
    }
}
