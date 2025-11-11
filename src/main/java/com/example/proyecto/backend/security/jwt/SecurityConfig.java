package com.example.proyecto.backend.security.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailsService uds;
    private final JwtFilter jwtFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // CSRF se desactiva porque JWT ya protege requests sin sesiones
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
		 // sin sesiones -> cada request debe venir con token
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // reglas de acceso
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()                 // ⬅️ nuevo (deja pasar forwards a /error)
                        .requestMatchers("/auth/login").permitAll() // única pública
                        .requestMatchers(HttpMethod.POST, "/api/public/signup").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated() // todo lo demás requiere token
                )
                // cargador de usuarios (de tu BD)
                .userDetailsService(uds)
                // filtro JWT antes del de usuario/contraseña
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
