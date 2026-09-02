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
    private String payloadEncrypted; // base64 of IV||ciphertext

    @Column(length = 64)
    private String payloadHash; // sha256 of plaintext payload

    private String timestamp;

    private Boolean archived = Boolean.FALSE;
    private String archivedAt;

    @Column(length = 64)
    private String contentHash;

    @Column(length = 64)
    private String prevHash;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String encryptedKey; // base64 encrypted data key (encrypted with master key)

    public AuditRecord(String eventType, String actorId, String resourceType, String resourceId, String payloadEncrypted, String payloadHash, String timestamp, String contentHash, String prevHash, String encryptedKey) {
        this.eventType = eventType;
        this.actorId = actorId;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.payloadEncrypted = payloadEncrypted;
        this.payloadHash = payloadHash;
        this.timestamp = timestamp;
        this.contentHash = contentHash;
        this.prevHash = prevHash;
        this.encryptedKey = encryptedKey;
    }
}
