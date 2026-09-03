package com.example.audit.web;

import java.util.List;

public class TokenValidationResponse {
    private boolean valid;
    private String username;
    private List<String> roles;

    public TokenValidationResponse() {
    }

    public TokenValidationResponse(boolean valid, String username, List<String> roles) {
        this.valid = valid;
        this.username = username;
        this.roles = roles;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
