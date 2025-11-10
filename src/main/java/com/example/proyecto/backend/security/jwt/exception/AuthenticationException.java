package com.example.proyecto.backend.security.jwt.exception;

public class AuthenticationException extends RuntimeException {
    public AuthenticationException(String message) { super(message); }
}