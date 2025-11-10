package com.example.proyecto.backend.dtos;

import java.util.List;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class TokenDTO {
    private String accessToken;
    private Long userId;
    private String email;
    private List<String> roles;
    private Long companyId; // puede ser null si el usuario no pertenece a empresa
}