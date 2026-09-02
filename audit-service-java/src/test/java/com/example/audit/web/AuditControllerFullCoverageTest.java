package com.example.audit.web;

import com.example.audit.model.AuditRecord;
import com.example.audit.service.AuditService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuditController.class)
@org.springframework.context.annotation.Import(com.example.audit.config.SecurityConfig.class)
public class AuditControllerFullCoverageTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    private AuditService svc;

    @Test
    void createSuccessAndBadRequest() throws Exception {
        Map<String,Object> payload = Map.of("foo","bar");
        AuditRecord rec = new AuditRecord("CREATE","actor1","type","rid","enc", "hash", "2026-09-02T00:00:00Z","ch","ph","ek");
        rec.setId(1L);
        when(svc.append(eq("TEST"), eq("a"), eq("t"), eq("r"), any(), any())).thenReturn(rec);

        String body = "{\"eventType\":\"TEST\",\"actorId\":\"a\",\"resourceType\":\"t\",\"resourceId\":\"r\",\"payload\":{\"foo\":\"bar\"}}";
        mvc.perform(post("/audit/events").with(httpBasic("user","userpass")).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1));

        String bad = "{\"actorId\":\"a\"}"; // missing required
        mvc.perform(post("/audit/events").with(httpBasic("user","userpass")).contentType(MediaType.APPLICATION_JSON).content(bad))
                .andExpect(status().isBadRequest());
    }

    @Test
    void queryIncludePayloadVariants() throws Exception {
        // payloadEncrypted is JSON string
        AuditRecord rJson = new AuditRecord("E","A","T","R","{\"x\":\"y\"}", "ph", "2026-09-02T00:00:00Z","ch","ph","ek");
        rJson.setId(10L);
        when(svc.query(any(), any(), any(), any(), any(), any(), anyInt(), anyInt())).thenReturn(new PageImpl<>(List.of(rJson)));
        when(svc.applyRedactionView(any())).thenAnswer(inv -> {
            AuditRecord orig = inv.getArgument(0);
            return orig; // already plaintext in payloadEncrypted
        });

        mvc.perform(get("/audit/events").with(httpBasic("user","userpass")).param("redacted", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].payload.x").value("y"));

        // payloadEncrypted plain string (non-JSON) -> payload should be the string
        AuditRecord rPlain = new AuditRecord("E","A","T","R","plain-text", "ph", "2026-09-02T00:00:00Z","ch","ph","ek");
        rPlain.setId(11L);
        when(svc.query(any(), any(), any(), any(), any(), any(), anyInt(), anyInt())).thenReturn(new PageImpl<>(List.of(rPlain)));
        when(svc.applyRedactionView(any())).thenAnswer(inv -> inv.getArgument(0));

        mvc.perform(get("/audit/events").with(httpBasic("user","userpass")).param("redacted", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].payload").value("plain-text"));

        // payloadEncrypted null -> payload should be null
        AuditRecord rNull = new AuditRecord("E","A","T","R",null, "ph", "2026-09-02T00:00:00Z","ch","ph",null);
        rNull.setId(12L);
        when(svc.query(any(), any(), any(), any(), any(), any(), anyInt(), anyInt())).thenReturn(new PageImpl<>(List.of(rNull)));
        when(svc.applyRedactionView(any())).thenAnswer(inv -> inv.getArgument(0));

        mvc.perform(get("/audit/events").with(httpBasic("user","userpass")).param("redacted", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].payload").doesNotExist());
    }

    @Test
    void handleFilterSupportedAndUnsupported() throws Exception {
        when(svc.query(any(), any(), any(), any(), any(), any(), anyInt(), anyInt())).thenReturn(new PageImpl<>(List.of()));

        mvc.perform(get("/audit/events/actorId").with(httpBasic("user","userpass")).param("value", "a"))
                .andExpect(status().isOk());
        mvc.perform(get("/audit/events/eventType").with(httpBasic("user","userpass")).param("value", "e"))
                .andExpect(status().isOk());
        mvc.perform(get("/audit/events/resourceType").with(httpBasic("user","userpass")).param("value", "t"))
                .andExpect(status().isOk());
        mvc.perform(get("/audit/events/resourceId").with(httpBasic("user","userpass")).param("value", "r"))
                .andExpect(status().isOk());
        // resource with colon
        mvc.perform(get("/audit/events/resource").with(httpBasic("user","userpass")).param("value", "type:id"))
                .andExpect(status().isOk());
        // resource without colon
        mvc.perform(get("/audit/events/resource").with(httpBasic("user","userpass")).param("value", "typeOnly"))
                .andExpect(status().isOk());

        // unsupported
        mvc.perform(get("/audit/events/unknown").with(httpBasic("user","userpass")).param("value", "x"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void redactSuccessAndFailure() throws Exception {
        when(svc.redactRecord(eq(5L), eq("red"), any())).thenReturn(new com.example.audit.model.RedactionRecord());

        String body = "{\"recordId\":5,\"redactorId\":\"red\",\"fields\":[\"payload.ssn\"]}";
        mvc.perform(post("/audit/redact").with(httpBasic("admin","adminpass")).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());

        when(svc.redactRecord(eq(6L), any(), any())).thenThrow(new RuntimeException("fail"));
        String body2 = "{\"recordId\":6}";
        mvc.perform(post("/audit/redact").with(httpBasic("admin","adminpass")).contentType(MediaType.APPLICATION_JSON).content(body2))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void eraseSuccessAndFailure() throws Exception {
        AuditRecord rec = new AuditRecord("E","A","T","R",null, "ph", "2026-09-02T00:00:00Z","ch","ph",null);
        rec.setId(20L);
        when(svc.eraseRecord(eq(20L), eq("er"))).thenReturn(rec);

        String body = "{\"recordId\":20,\"eraserId\":\"er\"}";
        mvc.perform(post("/audit/erase").with(httpBasic("admin","adminpass")).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(20));

        when(svc.eraseRecord(eq(21L), any())).thenThrow(new RuntimeException("nope"));
        String body2 = "{\"recordId\":21}";
        mvc.perform(post("/audit/erase").with(httpBasic("admin","adminpass")).contentType(MediaType.APPLICATION_JSON).content(body2))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void archiveEndpoint() throws Exception {
        when(svc.archiveOlderThanDays(7)).thenReturn(3);
        mvc.perform(post("/audit/archive").with(httpBasic("admin","adminpass")).param("days","7"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archived").value(3));
    }

    @Test
    void exportSuccessAndFailure() throws Exception {
        Map<String,Object> bundle = Map.of("exportedAt", "now", "records", List.of());
        when(svc.exportBundle(any(), any())).thenReturn(bundle);
        mvc.perform(get("/audit/export").with(httpBasic("admin","adminpass")).param("actorId","a"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exportedAt").value("now"));

        when(svc.exportBundle(any(), any())).thenThrow(new IllegalArgumentException("need param"));
        mvc.perform(get("/audit/export").with(httpBasic("admin","adminpass")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void verifyEndpoint() throws Exception {
        AuditService.VerificationResult vr = new AuditService.VerificationResult(true, -1, null, null);
        when(svc.verifyChain()).thenReturn(vr);
        mvc.perform(get("/audit/verify").with(httpBasic("user","userpass")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));
    }
}
