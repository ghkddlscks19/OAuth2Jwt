package com.example.oauth2jwt.oauth2;

import com.example.oauth2jwt.dto.CustomOAuth2user;
import com.example.oauth2jwt.jwt.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;

    public CustomSuccessHandler(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //OAuth2User
        CustomOAuth2user customUserDetails = (CustomOAuth2user) authentication.getPrincipal();

        //JWT 발급할 때 username과 role 값을 넣기로 설정했기 때문에 추출해야함
        //username 추출
        String username = customUserDetails.getUsername();
        //role 추출
        Collection<? extends GrantedAuthority> authorities = customUserDetails.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();


        String token = jwtUtil.createJwt(username, role, 60 * 60 * 60L);

        response.addCookie(createCookie("Authorization", token));
        response.sendRedirect("http://localhost:3000/");

    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60 * 60 * 60); //쿠키가 살아있을 시간
//        cookie.setSecure(true); https에서만 동작하도록 하는 설정(local 환경은 http이므로 주석처리)
        cookie.setPath("/"); //전역에서 쿠키 확인 가능
        cookie.setHttpOnly(true); //자바 스크립트가 쿠키를 가져가지 못하게 하는 설정

        return cookie;
    }

}
