package com.example.audit.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "audit_record")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class AuditRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String eventType;
    private String actorId;
    private String resourceType;
    private String resourceId;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String payload;

    private String timestamp;

    @Column(length = 64)
    private String contentHash;

    @Column(length = 64)
    private String prevHash;

    public AuditRecord(String eventType, String actorId, String resourceType, String resourceId, String payload, String timestamp, String contentHash, String prevHash) {
        this.eventType = eventType;
        this.actorId = actorId;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.payload = payload;
        this.timestamp = timestamp;
        this.contentHash = contentHash;
        this.prevHash = prevHash;
    }
}
