package com.cos.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.entity.Member;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// spring security에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청 시 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter 이 필터가 동작 함
// SecurityConfig에서 formLogin을 disable했기때문에
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // Spring Security에서 인증을 처리하는 핵심 인터페이스
    // 아이디/비번 받아서 인증을 확인하고
    // 성공하면 Authentication 객체를 반환해줌
    private final AuthenticationManager authenticationManager;

    // /login 요청 시 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter 로그인 시도");

        // 1. username, password 받아서

        // 2. 정상인지 로그인 시도 해보기,
        // authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출

        // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해)

        // 4. JWT 토큰을 만들어서 응답해주기

        try {
            /*BufferedReader br = request.getReader();
            String input = null;
            while ((input = br.readLine()) != null) {
                System.out.println(input);
            }*/
            ObjectMapper om = new ObjectMapper();
            Member member = om.readValue(request.getInputStream(), Member.class);
            System.out.println("member = " + member);

            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(member.getUsername(),
                    member.getPassword());

            // PrincipalDetailsService의 loadUserByUsername 호출
            // DB에 있는 username과 password가 일치한다
            Authentication authentication
                    = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료! => principalDetails = " + principalDetails.getMember());

            // 인증이 성공하면 authentication 객체가 session에 저장됨 => 로그인이 성공되었다는 뜻
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었다면
    // successfulAuthentication 함수 실행됨
    // 여기서 JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 응답해줌
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain chain,
                                            Authentication authResult)
            throws IOException, ServletException {

        System.out.println("successfulAuthentication 실행됨 : 인증완료!");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos 토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))
                .withClaim("id", principalDetails.getMember().getId())
                .withClaim("username", principalDetails.getMember().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
