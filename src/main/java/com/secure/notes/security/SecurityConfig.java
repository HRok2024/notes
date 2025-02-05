package com.secure.notes.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
        //http.formLogin(withDefaults());


        http.authorizeHttpRequests((requests) ->
                requests
                        .anyRequest().authenticated());
        http.csrf(AbstractHttpConfigurer::disable); //CSRF 중지(POST요청 시 CSRF토큰이 없으면 공격으로 간주)
        //http.formLogin( withDefaults());
        http.httpBasic(withDefaults());

        return http.build();
    }
}
