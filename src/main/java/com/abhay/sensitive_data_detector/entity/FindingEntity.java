package com.abhay.sensitive_data_detector.entity;



import jakarta.persistence.*;

@Entity
@Table(name = "findings")
public class FindingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String type;

    private String severity;

    private String maskedValue;

    private int frameNumber;

    private String method;

    private String uri;

    public FindingEntity() {
    }

    public FindingEntity(
            String type,
            String severity,
            String maskedValue,
            int frameNumber,
            String method,
            String uri) {

        this.type = type;
        this.severity = severity;
        this.maskedValue = maskedValue;
        this.frameNumber = frameNumber;
        this.method = method;
        this.uri = uri;
    }

    public Long getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMaskedValue() {
        return maskedValue;
    }

    public int getFrameNumber() {
        return frameNumber;
    }

    public String getMethod() {
        return method;
    }

    public String getUri() {
        return uri;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public void setMaskedValue(String maskedValue) {
        this.maskedValue = maskedValue;
    }

    public void setFrameNumber(int frameNumber) {
        this.frameNumber = frameNumber;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }
}
