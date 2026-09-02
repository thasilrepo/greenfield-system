package com.example.audit;

import com.example.audit.model.AuditRecord;
import com.example.audit.repo.AuditRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuditControllerIntegrationTest {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private AuditRecordRepository repo;

    @BeforeEach
    public void beforeEach() {
        repo.deleteAll();
    }

    @Test
    public void testCreateEvent_success_and_verify_chain() {
        Map<String, Object> body = new HashMap<>();
        body.put("eventType", "USER_LOGIN");
        body.put("actorId", "user-1");
        body.put("resourceType", "session");
        body.put("resourceId", "s1");
        Map<String, Object> payload = new HashMap<>();
        payload.put("ip", "1.2.3.4");
        body.put("payload", payload);

        ResponseEntity<Map> r = rest.postForEntity("/audit/events", body, Map.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Map<?,?> rec = r.getBody();
        assertThat(rec).isNotNull();
        assertThat(rec.get("id")).isNotNull();
        assertThat(rec.get("contentHash")).isNotNull();
        assertThat(rec.get("prevHash")).isNotNull();
        // verify chain endpoint
        ResponseEntity<Map> v = rest.getForEntity("/audit/verify", Map.class);
        assertThat(v.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?,?> m = v.getBody();
        assertThat(m).isNotNull();
        assertThat(m.get("intact")).isEqualTo(Boolean.TRUE);
    }

    @Test
    public void testCreateEvent_missingFields_negative() {
        Map<String, Object> body = new HashMap<>();
        body.put("eventType", "USER_LOGIN");
        // missing actorId
        body.put("resourceType", "session");
        body.put("resourceId", "s1");

        ResponseEntity<String> r = rest.postForEntity("/audit/events", body, String.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void testQueryFilters_and_pagination() {
        // create 3 events
        for (int i = 1; i <= 3; i++) {
            Map<String, Object> b = new HashMap<>();
            b.put("eventType", i % 2 == 0 ? "RECORD_UPDATED" : "USER_LOGIN");
            b.put("actorId", "actor-" + (i%2));
            b.put("resourceType", "order");
            b.put("resourceId", "order-1");
            rest.postForEntity("/audit/events", b, Map.class);
        }
        // query actorId=actor-1 using query param
        ResponseEntity<Map> resp = rest.getForEntity("/audit/events?actorId=actor-1&limit=2&page=1", Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?,?> body = resp.getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("total")).isNotNull();
        assertThat(((List<?>) body.get("items")).size()).isLessThanOrEqualTo(2);

        // page 2
        ResponseEntity<Map> resp2 = rest.getForEntity("/audit/events?actorId=actor-1&limit=2&page=2", Map.class);
        assertThat(resp2.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testQueryByField_pathStyle() {
        // create 3 events
        for (int i = 1; i <= 3; i++) {
            Map<String, Object> b = new HashMap<>();
            b.put("eventType", i % 2 == 0 ? "RECORD_UPDATED" : "USER_LOGIN");
            b.put("actorId", "actor-" + (i%2));
            b.put("resourceType", "order");
            b.put("resourceId", "order-1");
            rest.postForEntity("/audit/events", b, Map.class);
        }

        // use path-style filter endpoint (query param version)
        ResponseEntity<Map> resp = rest.getForEntity("/audit/events/actorId?value=actor-1&limit=2&page=1", Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?,?> body = resp.getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("total")).isNotNull();
        assertThat(((List<?>) body.get("items")).size()).isLessThanOrEqualTo(2);

        // use path-style filter endpoint (path param version)
        ResponseEntity<Map> respPath = rest.getForEntity("/audit/events/actorId/actor-1?limit=2&page=1", Map.class);
        assertThat(respPath.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?,?> body2 = respPath.getBody();
        assertThat(body2).isNotNull();
        assertThat(body2.get("total")).isNotNull();
        assertThat(((List<?>) body2.get("items")).size()).isLessThanOrEqualTo(2);
    }

    @Test
    public void testVerifyChain_detects_tamper() throws Exception {
        // create two events
        Map<String, Object> b1 = new HashMap<>();
        b1.put("eventType", "USER_LOGIN");
        b1.put("actorId", "u1");
        b1.put("resourceType", "session");
        b1.put("resourceId", "s1");
        rest.postForEntity("/audit/events", b1, Map.class);

        Map<String, Object> b2 = new HashMap<>();
        b2.put("eventType", "RECORD_UPDATED");
        b2.put("actorId", "u2");
        b2.put("resourceType", "order");
        b2.put("resourceId", "o1");
        rest.postForEntity("/audit/events", b2, Map.class);

        List<AuditRecord> all = repo.findAll();
        assertThat(all.size()).isEqualTo(2);
        AuditRecord first = all.get(0);
        // tamper by modifying the stored contentHash to an invalid value
        first.setContentHash("invalidtamper");
        repo.save(first);

        ResponseEntity<Map> v = rest.getForEntity("/audit/verify", Map.class);
        assertThat(v.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?,?> m = v.getBody();
        assertThat(m).isNotNull();
        assertThat(m.get("intact")).isEqualTo(Boolean.FALSE);
        assertThat(m.get("reason")).isEqualTo("content_hash_mismatch");
        assertThat(((Number)m.get("recordId")).longValue()).isEqualTo(first.getId().longValue());
    }

    @Test
    public void testErase_makes_payload_unavailable() throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("eventType", "USER_LOGIN");
        body.put("actorId", "user-erase");
        body.put("resourceType", "session");
        body.put("resourceId", "s2");
        Map<String, Object> payload = new HashMap<>();
        payload.put("secret", "top-secret");
        body.put("payload", payload);

        ResponseEntity<Map> created = rest.postForEntity("/audit/events", body, Map.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Map<?,?> recMap = created.getBody();
        assertThat(recMap).isNotNull();
        Number idNum = (Number) recMap.get("id");
        Long id = idNum.longValue();

        AuditRecord rec = repo.findById(id).orElseThrow();
        assertThat(rec.getEncryptedKey()).isNotNull();
        assertThat(rec.getPayloadEncrypted()).isNotNull();

        Map<String,Object> eraseReq = new HashMap<>();
        eraseReq.put("recordId", id);
        eraseReq.put("eraserId", "tester");
        ResponseEntity<Map> er = rest.postForEntity("/audit/erase", eraseReq, Map.class);
        assertThat(er.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?,?> erBody = er.getBody();
        assertThat(erBody).isNotNull();
        assertThat(erBody.get("payloadAvailable")).isEqualTo(Boolean.FALSE);

        AuditRecord after = repo.findById(id).orElseThrow();
        assertThat(after.getEncryptedKey()).isNull();
    }
}
