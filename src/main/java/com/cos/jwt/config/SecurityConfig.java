package com.cos.jwt.config;

import com.cos.jwt.filter.JwtAuthenticationFilter;
import com.cos.jwt.filter.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final MemberRepository memberRepository;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {

        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();

        //http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(sm ->
                        // 세션을 사용하지 않겠다
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(corsConfig.corsFilter())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .addFilter(new JwtAuthenticationFilter(authenticationManager))
                .addFilter(new JwtAuthorizationFilter(authenticationManager, memberRepository));

        http.authorizeHttpRequests(auth
                -> auth.requestMatchers("/api/v1/user/**")
                .hasAnyRole("USER", "ADMIN", "MANAGER")
                .requestMatchers("/api/v1/manager/**")
                .hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers("/api/v1/admin/**")
                .hasRole("ADMIN")
                .anyRequest().permitAll());

        return http.build();
    }

}
