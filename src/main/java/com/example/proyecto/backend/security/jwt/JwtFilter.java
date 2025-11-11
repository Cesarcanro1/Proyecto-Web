package com.example.proyecto.backend.security.jwt;

import java.io.IOException;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

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

    // ✅ rutas públicas que NO requieren token
    private static final Set<String> WHITE_LIST = Set.of(
            "/error",                 // ⬅️ nuevo
            "/auth/login",
            "/api/public",          // base
            "/api/public/",         // con slash
            "/api/public/signup"    // endpoint exacto
    );

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
        ) throws ServletException, IOException {

        System.out.println(">>> JWT path = " + request.getRequestURI() + " | method = " + request.getMethod());

        // 0️⃣: Preflight CORS: siempre dejar pasar
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        // 1️⃣: Normaliza path
        String uri = request.getRequestURI(); // ej: /api/public/signup
        String ctx = request.getContextPath();
        String path = (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx))
                ? uri.substring(ctx.length())
                : uri;

        // 2️⃣: Log temporal para debug
        // System.out.println(">>> JWT Filter path: " + path);

        // 3️⃣: Si es ruta pública -> seguir sin tocar auth
        if (isWhitelisted(path)) {
            chain.doFilter(request, response);
            return;
        }

        // 4️⃣: Si ya hay auth -> seguir
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        // 5️⃣: Lee Authorization
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // sin token -> no bloquees, deja que SecurityConfig decida
            chain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);
        try {
            final String username = jwtUtil.extractUsername(token);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                var user = uds.loadUserByUsername(username);
                if (jwtUtil.isValid(token, user)) {
                    var authToken = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception ignored) {
            // no rompas el flujo, deja que SecurityConfig responda 401/403
        }

        chain.doFilter(request, response);
    }

    private boolean isWhitelisted(String path) {
        if (path == null) return false;
        // Permite exactos y cualquier subruta (como /api/public/signup)
        return WHITE_LIST.stream().anyMatch(w ->
                path.equals(w) || path.startsWith(w + "/")
        );
    }
}