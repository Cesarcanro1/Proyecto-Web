package com.example.proyecto.backend.security.jwt;

import java.util.List;

import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.proyecto.backend.repository.UsuarioRepository;

@Service
@Transactional(readOnly = true)
public class CustomUserDetailsService implements UserDetailsService {

    private final UsuarioRepository userRepo;

    public CustomUserDetailsService(UsuarioRepository userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        var u = userRepo.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Not found"));

        // solo permiten login los status == 0
        if (u.getStatus() != 0) {
            throw new DisabledException("User soft-deleted");
        }

        // Por ahora, rol por defecto 
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        return User.builder()
                .username(u.getEmail())     // unique
                .password(u.getPassword())  // BCrypt
                .authorities(authorities)
                .disabled(false)            // ya validamos status arriba
                .accountExpired(false)
                .credentialsExpired(false)
                .accountLocked(false)
                .build();
    }
}
