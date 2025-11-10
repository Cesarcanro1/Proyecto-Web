package com.example.proyecto.backend.security.jwt.web;

import com.example.proyecto.backend.dtos.LoginDTO;
import com.example.proyecto.backend.security.jwt.CustomUserDetailsService;
import com.example.proyecto.backend.security.jwt.JwtUtil;
import com.example.proyecto.backend.repository.UsuarioRepository;
import com.example.proyecto.backend.dtos.TokenDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService uds;
    private final UsuarioRepository userRepo;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO dto) {
        try {
            // 1. Autenticamos con el AuthenticationManager de Spring
            var tokenReq = new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword());
            authManager.authenticate(tokenReq);

            // 2. Traemos el usuario desde BD
            var u = userRepo.findByEmail(dto.getEmail())
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

            // 3. Cargamos datos del UserDetails
            UserDetails user = uds.loadUserByUsername(dto.getEmail());

            // 4. Claims adicionales para el JWT
            var claims = new HashMap<String, Object>();
            claims.put("userId", u.getId());
            claims.put("roles", List.of("ROLE_USER")); // por ahora, rol fijo
            if (u.getEmpresa() != null) {
                claims.put("companyId", u.getEmpresa().getId());
            }

            // 5. Generamos el token
            String accessToken = jwtUtil.generateAccessToken(user, claims);

            // 6. Armamos la respuesta (TokenDTO)
            TokenDTO out = new TokenDTO();
            out.setAccessToken(accessToken);
            out.setUserId(u.getId());
            out.setEmail(u.getEmail());
            out.setRoles(List.of("USER"));
            out.setCompanyId(u.getEmpresa() != null ? u.getEmpresa().getId() : null);

            return ResponseEntity.ok(out);

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Credenciales incorrectas");
        } catch (DisabledException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Usuario deshabilitado o eliminado");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al procesar el login");
        }
    }
}
