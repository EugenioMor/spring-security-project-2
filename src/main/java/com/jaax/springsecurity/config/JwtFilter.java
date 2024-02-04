package com.jaax.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//Este método se va a ejecutar una vez en cada petición que se haga
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {//Creamos el filtro de autenticación

    @Autowired
    private final UserDetailsService userDetailsService;

    @Autowired
    private final JwtService jwtService;
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, //Lo que el cliente envía en la petición
                                    @NonNull HttpServletResponse response, //La respuesta que le damos al cliente una vez que es procesada su petición
                                    @NonNull FilterChain filterChain) //Elemento que nos va a permitir continuar con el proceso de la solicitud una vez que lo hayamos filtrado
                                    throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization"); //Obtengo el header de autorizacion, que viene en el request
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request,response);
            return; //Envío status 403 porque no me está enviando las credenciales de acceso
        }

        jwt = authHeader.substring(7); //Porque cuando se envía la petición con un bearear siempre empieza con: "Bearer sdffsdfs";
        userEmail = jwtService.getUserName(jwt);

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){ //que el usuario no sea nulo y que no esté autenticado
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.validateToken(jwt,userDetails)){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
