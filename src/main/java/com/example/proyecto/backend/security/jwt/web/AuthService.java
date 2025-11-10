package com.example.proyecto.backend.security.jwt.web;

import com.example.proyecto.backend.dtos.LoginDTO;
import com.example.proyecto.backend.repository.UsuarioRepository;
import com.example.proyecto.backend.security.jwt.CustomUserDetailsService;
import com.example.proyecto.backend.security.jwt.JwtUtil;
import com.example.proyecto.backend.security.jwt.exception.AuthenticationException;
import com.example.proyecto.backend.dtos.TokenDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService uds;
    private final UsuarioRepository userRepo;

    public TokenDTO login(LoginDTO dto) {
        try {
            var tokenReq = new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword());
            authManager.authenticate(tokenReq);

            var u = userRepo.findByEmail(dto.getEmail())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuario no encontrado"));

            UserDetails user = uds.loadUserByUsername(dto.getEmail());

            var claims = new HashMap<String, Object>();
            claims.put("userId", u.getId());
            claims.put("roles", List.of("ROLE_USER")); // por ahora fijo
            if (u.getEmpresa() != null) claims.put("companyId", u.getEmpresa().getId());

            String accessToken = jwtUtil.generateAccessToken(user, claims);

            var out = new TokenDTO();
            out.setAccessToken(accessToken);
            out.setUserId(u.getId());
            out.setEmail(u.getEmail());
            out.setRoles(List.of("USER"));
            out.setCompanyId(u.getEmpresa() != null ? u.getEmpresa().getId() : null);
            return out;

        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales incorrectas");
        } catch (DisabledException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuario deshabilitado o eliminado");
        } catch (AuthenticationException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No autorizado");
        }
    }
}
