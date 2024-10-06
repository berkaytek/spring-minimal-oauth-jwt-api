package com.central.auth.config;

import com.central.auth.utils.JwtUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtUtils jwtUtils;

    public SecurityConfig(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/api/v1/auth/**", "/login/**", "/logout/**", "/actuator/**", "/oauth2/**")
                                .permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login
                                .successHandler((request, response, authentication) -> {
                                    DefaultOAuth2User user = (DefaultOAuth2User) authentication.getPrincipal();
                                    String jwtToken = this.jwtUtils.createJwtToken(user.getAttribute("login"));
                                    this.jwtUtils.setJwtCookie(response, jwtToken);
                                    response.sendRedirect("/");
                                })
                )
                .logout(logout ->
                        logout
                                .logoutUrl("/logout")
                                .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/api/v1/auth/status"))
                                .invalidateHttpSession(true)
                                .clearAuthentication(true)
                                .deleteCookies("JWT_TOKEN", "JSESSIONID")
                )
                .csrf(AbstractHttpConfigurer::disable); // Disable CSRF for simplicity (configure properly in production)
        return http.build();
    }
}
