package io.javabrains.springsecurityjwt.models;

import javax.persistence.*;

@Entity
@Table(name = "tasks")
public class Task {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "description")
    private String description;

    @Column(name = "status")
    private String status;

    @Column(name = "username") // Asegúrate de que este nombre coincida con el campo en la base de datos
    private String username;

    // Constructor por defecto
    public Task() {}

    // Constructor con parámetros
    public Task(Long id, String description, String status, String username) {
        this.id = id;
        this.description = description;
        this.status = status;
        this.username = username;
    }

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}