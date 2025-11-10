package com.example.proyecto.backend.security.jwt;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.example.proyecto.backend.repository.UsuarioRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class SecurityUtils {

    private final UsuarioRepository userRepo;

    public String currentEmail() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return (auth != null) ? auth.getName() : null;
    }

    public Long currentCompanyId() {
        var email = currentEmail();
        if (email == null) return null;
        return userRepo.findByEmail(email)
                .map(u -> u.getEmpresa() != null ? u.getEmpresa().getId() : null)
                .orElse(null);
    }

    public Long currentUserId() {
        var email = currentEmail();
        if (email == null) return null;
        return userRepo.findByEmail(email)
                .map(u -> u.getId())
                .orElse(null);
    }
}
