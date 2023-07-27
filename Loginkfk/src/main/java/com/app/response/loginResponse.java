package com.app.response;

import jakarta.persistence.Column;

public class loginResponse {
    private int Id;

    private String name;

    private String email;

    private String role;

    public loginResponse(int id, String name, String email, String role) {
        Id = id;
        this.name = name;
        this.email = email;
        this.role = role;

    }

    public int getId() {
        return Id;
    }

    public void setId(int id) {
        Id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
