package com.example.oauth2jwt.config;

import com.example.oauth2jwt.oauth2.CustomClientRegistrationRepo;
import com.example.oauth2jwt.service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomClientRegistrationRepo customClientRegistrationRepo;
    private final CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfig(CustomClientRegistrationRepo customClientRegistrationRepo, CustomOAuth2UserService customOAuth2UserService) {
        this.customClientRegistrationRepo = customClientRegistrationRepo;
        this.customOAuth2UserService = customOAuth2UserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //csrf disable
        http
                .csrf((csrf) -> csrf.disable());
        //formLogin disable
        http
                .formLogin((auth) -> auth.disable());
        //httpBasic disable
        http
                .httpBasic((auth) -> auth.disable());
        //oauth2 설정
        http
                .oauth2Login((oauth2) -> oauth2
                        .clientRegistrationRepository(customClientRegistrationRepo.clientRegistrationRepository())
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService)));

        return http.build();
    }
}
