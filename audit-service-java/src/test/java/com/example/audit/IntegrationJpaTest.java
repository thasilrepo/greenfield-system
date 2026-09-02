package com.example.audit;

import com.example.audit.model.AuditRecord;
import com.example.audit.model.RedactionRecord;
import com.example.audit.repo.AuditRecordRepository;
import com.example.audit.repo.RedactionRecordRepository;
import com.example.audit.service.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
public class IntegrationJpaTest {

    @Autowired
    private AuditService svc;

    @Autowired
    private AuditRecordRepository repo;

    @Autowired
    private RedactionRecordRepository redactionRepo;

    @BeforeEach
    void before() {
        redactionRepo.deleteAll();
        repo.deleteAll();
    }

    @Test
    void appendQueryExportAndArchive_viaService_andRepo() {
        // append two records
        AuditRecord a1 = svc.append("EV1","actor-a","type","r1", Map.of("k","v"), Instant.now().minus(Duration.ofDays(10)).toString());
        AuditRecord a2 = svc.append("EV2","actor-b","type","r2", Map.of("k2","v2"), Instant.now().toString());

        assertThat(a1.getId()).isNotNull();
        assertThat(a2.getId()).isNotNull();

        // query by actor via specification path
        var page = svc.query(Optional.of("actor-a"), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 1, 10);
        assertThat(page.getTotalElements()).isEqualTo(1);

        // export by actor
        var bundle = svc.exportBundle(Optional.of("actor-a"), Optional.empty());
        assertThat(bundle).isNotNull();
        List<?> recs = (List<?>) bundle.get("records");
        assertThat(recs.size()).isEqualTo(1);

        // archive older than 5 days should archive the older record
        int count = svc.archiveOlderThanDays(5);
        assertThat(count).isGreaterThanOrEqualTo(1);

        // re-export and confirm archived flag present
        var bundle2 = svc.exportBundle(Optional.of("actor-a"), Optional.empty());
        List<?> recs2 = (List<?>) bundle2.get("records");
        Map<?,?> exported = (Map<?,?>) recs2.get(0);
        assertThat(exported.get("archived")).isEqualTo(Boolean.TRUE);
    }

    @Test
    void applyRedactionView_withStoredRedaction_keepsEncryptedKeyAndRedacts() throws Exception {
        // append record
        AuditRecord created = svc.append("LOGIN","redactor","session","s-red", Map.of("user", Map.of("ssn","999-99-9999","name","Bob")), null);
        assertThat(created.getEncryptedKey()).isNotNull();

        // create redaction metadata directly (simulate a privacy metadata entry) without deleting key
        RedactionRecord rr = new RedactionRecord();
        rr.setTargetRecordId(created.getId());
        rr.setRedactorId("tester");
        rr.setFieldsJson("[\"user.ssn\"]");
        rr.setOriginalPayloadHash(created.getPayloadHash());
        rr.setTimestamp(Instant.now().toString());
        redactionRepo.save(rr);

        // fetch record from repo and apply redaction view
        AuditRecord fromDb = repo.findById(created.getId()).orElseThrow();
        AuditRecord view = svc.applyRedactionView(fromDb);
        assertThat(view).isNotNull();
        String payloadPlain = view.getPayloadEncrypted();
        assertThat(payloadPlain).doesNotContain("999-99-9999");
        assertThat(payloadPlain).contains("Bob");
    }

    @Test
    void querySpecification_filtersAndPagination() {
        Instant base = Instant.now();
        String t1 = base.minusSeconds(300).toString();
        String t2 = base.minusSeconds(240).toString();
        String t3 = base.minusSeconds(180).toString();
        String t4 = base.minusSeconds(120).toString();
        String t5 = base.minusSeconds(60).toString();

        // create a mix of records
        svc.append("EV","actor-x","typeA","r1", Map.of("k","v1"), t1);
        svc.append("EV","actor-x","typeA","r2", Map.of("k","v2"), t2);
        svc.append("EV","actor-x","typeB","r3", Map.of("k","v3"), t3);
        svc.append("EV2","actor-x","typeA","r4", Map.of("k","v4"), t4);
        svc.append("EV2","actor-y","typeA","r5", Map.of("k","v5"), t5);

        // filter by resourceType
        var pageTypeA = svc.query(Optional.empty(), Optional.of("typeA"), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 1, 10);
        assertThat(pageTypeA.getTotalElements()).isEqualTo(4);

        // filter by actor + resourceType
        var pageActorType = svc.query(Optional.of("actor-x"), Optional.of("typeA"), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 1, 10);
        assertThat(pageActorType.getTotalElements()).isEqualTo(3);

        // filter by timestamp range (inclusive)
        var pageFromTo = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(t2), Optional.of(t4), 1, 10);
        assertThat(pageFromTo.getTotalElements()).isEqualTo(3);

        // pagination: limit 2
        var p1 = svc.query(Optional.of("actor-x"), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 1, 2);
        var p2 = svc.query(Optional.of("actor-x"), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 2, 2);
        assertThat(p1.getSize()).isEqualTo(2);
        assertThat(p1.getTotalElements()).isEqualTo(4);
        assertThat(p2.getNumber()).isEqualTo(1);
        assertThat(p2.getNumberOfElements()).isGreaterThanOrEqualTo(1);

        // limit 0 should be treated as 1 (min page size)
        var p0 = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 1, 0);
        assertThat(p0.getSize()).isEqualTo(1);
    }

    @Test
    void querySpecification_allFiltersAndBounds() {
        Instant base = Instant.now();
        String t1 = base.minusSeconds(600).toString();
        String t2 = base.minusSeconds(500).toString();
        String t3 = base.minusSeconds(400).toString();
        String t4 = base.minusSeconds(300).toString();
        String t5 = base.minusSeconds(200).toString();
        String t6 = base.minusSeconds(100).toString();

        // insert records covering various fields
        svc.append("A","actor1","type1","res1", Map.of("k","v1"), t1);
        svc.append("B","actor2","type2","res2", Map.of("k","v2"), t2);
        svc.append("A","actor1","type2","res3", Map.of("k","v3"), t3);
        svc.append("C","actor3","type1","res4", Map.of("k","v4"), t4);
        svc.append("A","actor1","type1","res5", Map.of("k","v5"), t5);
        svc.append("B","actor2","type1","res6", Map.of("k","v6"), t6);

        // resourceId filter
        var pres3 = svc.query(Optional.empty(), Optional.empty(), Optional.of("res3"), Optional.empty(), Optional.empty(), Optional.empty(), 1, 10);
        assertThat(pres3.getTotalElements()).isEqualTo(1);

        // eventType filter
        var pevtA = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.of("A"), Optional.empty(), Optional.empty(), 1, 10);
        assertThat(pevtA.getTotalElements()).isEqualTo(3);

        // from only
        var pfrom = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(t3), Optional.empty(), 1, 10);
        assertThat(pfrom.getTotalElements()).isEqualTo(4);

        // to only
        var pto = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(t3), 1, 10);
        assertThat(pto.getTotalElements()).isEqualTo(3);

        // from-to range
        var prange = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(t2), Optional.of(t5), 1, 10);
        assertThat(prange.getTotalElements()).isEqualTo(4);

        // page/limit boundary behavior
        var pZero = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0);
        assertThat(pZero.getSize()).isEqualTo(1);

        var pLargeLimit = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 1, 200);
        assertThat(pLargeLimit.getSize()).isEqualTo(100);

        var pNegativePage = svc.query(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), -5, 10);
        assertThat(pNegativePage.getNumber()).isEqualTo(0);
    }
}
