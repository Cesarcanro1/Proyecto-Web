package com.example.proyecto.backend.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ErrorMessageDTO {
    private int status;
    private String error;
    private String message;
    private String path;
}