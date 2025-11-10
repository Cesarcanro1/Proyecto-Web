package com.example.proyecto.backend.security.jwt;

import java.io.IOException;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService uds;

    // Solo lo que quieras público. Por ahora, solo login.
    private static final Set<String> WHITE_LIST = Set.of(
            "/auth/login"
            // , "/health", "/ping"  // si luego necesitas más, las agregas acá
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        final String path = request.getRequestURI();

        // 1) Rutas públicas no requieren token
        if (isWhitelisted(path)) {
            chain.doFilter(request, response);
            return;
        }

        // 2) Si ya hay auth en el contexto, seguimos
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        // 3) Leer header Authorization
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);

        try {
            final String username = jwtUtil.extractUsername(token);
            if (username != null) {
                var user = uds.loadUserByUsername(username);
                if (jwtUtil.isValid(token, user)) {
                    var authToken = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (JwtException | IllegalArgumentException ignored) {
            // Dejamos que la chain continúe; SecurityConfig decidirá 401/403
        }

        chain.doFilter(request, response);
    }

    private boolean isWhitelisted(String path) {
        if (path == null) return false;
        return WHITE_LIST.stream().anyMatch(w ->
                path.equals(w) || path.startsWith(w + "/")
        );
    }
}
