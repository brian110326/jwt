package com.cos.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // 토큰 : cos 이걸 만들어줘야함
        // id, pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
        // 요청할 때마다 header에 Authorization의 value값에 토큰을 가지고온다.
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면됨

        if (request.getMethod().equals("POST")) {
            System.out.println("POST 요청됨");
            String headerAuth = request.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);

            System.out.println("필터3");

            if (headerAuth.equals("cos")) {
                filterChain.doFilter(request, response);
            } else {
                response.setCharacterEncoding("UTF-8");
                PrintWriter outPrintWriter = response.getWriter();
                outPrintWriter.println("인증안됨");
            }
        }
    }
}
