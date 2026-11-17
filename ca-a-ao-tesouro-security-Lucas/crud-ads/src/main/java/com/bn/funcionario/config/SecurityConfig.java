package com.bn.funcionario.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // API REST: sem formulario, entao o CSRF e desligado
                .csrf(csrf -> csrf.disable())
                // sem sessao: toda requisicao protegida precisa mandar o Basic Auth
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // libera a pagina de erro para os status reais (404, 500...) aparecerem
                        .requestMatchers("/error").permitAll()
                        // libera todas as requisicoes GET
                        .requestMatchers(HttpMethod.GET, "/api/**").permitAll()
                        // libera todas as requisicoes POST
                        .requestMatchers(HttpMethod.POST, "/api/**").permitAll()
                        // exige autenticacao para PUT
                        .requestMatchers(HttpMethod.PUT, "/api/**").authenticated()
                        // exige autenticacao para DELETE
                        .requestMatchers(HttpMethod.DELETE, "/api/**").authenticated()
                        // qualquer outra requisicao tambem exige autenticacao
                        .anyRequest().authenticated()
                )
                // autenticacao HTTP Basic (Postman: Authorization > Basic Auth)
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
