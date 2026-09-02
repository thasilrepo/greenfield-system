package com.example.audit.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "redaction_record")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RedactionRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long targetRecordId; // audit_record.id
    private String redactorId;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String fieldsJson; // JSON array of field paths to redact

    private String originalPayloadHash;
    private String timestamp;
}
