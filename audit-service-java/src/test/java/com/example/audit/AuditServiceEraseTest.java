package com.example.audit;

import com.example.audit.model.AuditRecord;
import com.example.audit.repo.AuditRecordRepository;
import com.example.audit.service.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class AuditServiceEraseTest {

    @Autowired
    private AuditService svc;

    @Autowired
    private AuditRecordRepository repo;

    @BeforeEach
    public void beforeEach() {
        repo.deleteAll();
    }

    @Test
    public void testEraseRecord_directServiceCall() {
        Map<String,Object> payload = new HashMap<>();
        payload.put("secret", "value-to-erase");

        AuditRecord created = svc.append("USER_LOGIN", "svc-user", "session", "sess-erase", payload, null);
        assertThat(created).isNotNull();
        assertThat(created.getId()).isNotNull();
        assertThat(created.getEncryptedKey()).isNotNull();
        assertThat(created.getPayloadEncrypted()).isNotNull();

        long beforeCount = repo.count();

        AuditRecord erased = svc.eraseRecord(created.getId(), "unit-tester");
        assertThat(erased).isNotNull();
        assertThat(erased.getId()).isEqualTo(created.getId());
        // encryptedKey should be removed
        assertThat(erased.getEncryptedKey()).isNull();

        AuditRecord fromDb = repo.findById(created.getId()).orElseThrow();
        assertThat(fromDb.getEncryptedKey()).isNull();

        // an ERASE audit event should have been appended (count increased by 1)
        assertThat(repo.count()).isEqualTo(beforeCount + 1);
    }
}
