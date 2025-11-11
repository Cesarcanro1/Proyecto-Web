package com.example.proyecto.backend.security.jwt.web;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.proyecto.backend.entity.Empresa;
import com.example.proyecto.backend.entity.Usuario;
import com.example.proyecto.backend.repository.EmpresaRepository;
import com.example.proyecto.backend.repository.UsuarioRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicSignupController {

  private final UsuarioRepository usuarioRepo;
  private final EmpresaRepository empresaRepo;
  private final PasswordEncoder passwordEncoder;

  @PostMapping("/signup")
  public ResponseEntity<?> signup(@RequestBody SignupRequest req) {
    if (usuarioRepo.count() > 0) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .body("El registro público ya no está disponible");
    }

    if (empresaRepo.findByNit(req.empresa.nit()).isPresent()) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body("NIT ya existe");
    }

    if (usuarioRepo.existsByEmail(req.usuario.email().trim().toLowerCase())) {
      return ResponseEntity.status(HttpStatus.CONFLICT).body("Email ya existe");
    }

    Empresa e = new Empresa();
    e.setNombre(req.empresa.nombre());
    e.setNit(req.empresa.nit());
    e.setCorreoContacto(req.empresa.correoContacto());
    e.setStatus(0);
    e = empresaRepo.save(e);

    Usuario u = new Usuario();
    u.setEmpresa(e);
    u.setNombres(req.usuario.nombres());
    u.setApellidos(req.usuario.apellidos());
    u.setEmail(req.usuario.email().trim().toLowerCase());
    u.setPassword(passwordEncoder.encode(req.usuario.password())); // hash!
    u.setStatus(0);
    u = usuarioRepo.save(u);

    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
      "empresaId", e.getId(),
      "usuarioId", u.getId()
    ));
  }

  public record SignupRequest(
    EmpresaReq empresa,
    UsuarioReq usuario
  ) {}
  public record EmpresaReq(String nombre, String nit, String correoContacto) {}
  public record UsuarioReq(String nombres, String apellidos, String email, String password) {}
}