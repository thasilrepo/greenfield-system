package com.example.audit.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_record")
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

    private Instant timestamp;

    @Column(length = 64)
    private String contentHash;

    @Column(length = 64)
    private String prevHash;

    public AuditRecord() {}

    public AuditRecord(String eventType, String actorId, String resourceType, String resourceId, String payload, Instant timestamp, String contentHash, String prevHash) {
        this.eventType = eventType;
        this.actorId = actorId;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.payload = payload;
        this.timestamp = timestamp;
        this.contentHash = contentHash;
        this.prevHash = prevHash;
    }

    // getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    public String getActorId() { return actorId; }
    public void setActorId(String actorId) { this.actorId = actorId; }
    public String getResourceType() { return resourceType; }
    public void setResourceType(String resourceType) { this.resourceType = resourceType; }
    public String getResourceId() { return resourceId; }
    public void setResourceId(String resourceId) { this.resourceId = resourceId; }
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    public String getContentHash() { return contentHash; }
    public void setContentHash(String contentHash) { this.contentHash = contentHash; }
    public String getPrevHash() { return prevHash; }
    public void setPrevHash(String prevHash) { this.prevHash = prevHash; }
}
