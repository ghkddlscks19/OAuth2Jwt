package com.example.oauth2jwt.config;

import com.example.oauth2jwt.jwt.JwtFilter;
import com.example.oauth2jwt.jwt.JwtUtil;
import com.example.oauth2jwt.oauth2.CustomClientRegistrationRepo;
import com.example.oauth2jwt.oauth2.CustomSuccessHandler;
import com.example.oauth2jwt.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomClientRegistrationRepo customClientRegistrationRepo;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JwtUtil jwtUtil;

    public SecurityConfig(CustomClientRegistrationRepo customClientRegistrationRepo, CustomOAuth2UserService customOAuth2UserService, CustomSuccessHandler customSuccessHandler, JwtUtil jwtUtil) {
        this.customClientRegistrationRepo = customClientRegistrationRepo;
        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //cors 설정
        http
                .cors((corsCustomizer) -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000")); //프론트 주소
                        configuration.setAllowedMethods(Collections.singletonList("*")); //get, put, post 등 모든 요청 허용
                        configuration.setAllowCredentials(true); //credential 값 가지고 올 수 있도록 허용
                        configuration.setAllowedHeaders(Collections.singletonList("*")); //어떤 헤더를 받을 수 있는지 설정
                        configuration.setMaxAge(3600L);

                        //우리가 데이터를 줄 경우 웹페이지에서 보이게 할 수 있는 방법
                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                }));
        //csrf disable
        http
                .csrf((csrf) -> csrf.disable());
        //formLogin disable
        http
                .formLogin((auth) -> auth.disable());
        //httpBasic disable
        http
                .httpBasic((auth) -> auth.disable());
        //필터 등록
        http
                .addFilterBefore(new JwtFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        //oauth2 설정
        http
                .oauth2Login((oauth2) -> oauth2
                        .clientRegistrationRepository(customClientRegistrationRepo.clientRegistrationRepository())
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler));
        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated());
        //세션 설정 STATELESS
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
