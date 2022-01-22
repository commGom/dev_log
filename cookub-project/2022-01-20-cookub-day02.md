## 개발 일지 2일차

날짜 : 2022-01-20 (목요일)

## Mindset

> 성실하게 확실하게

## Quote

> 간단함이 훌륭함의 열쇠다. -이소룡

## To Do List (Today)

- ~~Spring Security~~
- ~~JWT(JSON Web Token)~~
- ~~Filter 설정하기~~
- ~~로그인 구현하기~~

## What I learned

```plain
  시큐리티, JWT 같이 적용하는 것의 어려움
  SpringConfig에서 filter 적용 추가할 때,
  .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
  Filter를 이용하면서 doFilter를 잘 이용하자
  (요청받은 경로에 따라 Filter를 진행할지(JWT Token 검사) 바로 넘겨보낼지 결정)
```

**SpringConfig**

```java
package com.cookub.backend.config;

import com.cookub.backend.auth.UserDetailService;
import com.cookub.backend.filter.JwtRequestFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configurable
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailService userDetailService;
    private final JwtRequestFilter jwtRequestFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    /**
     * 데이터베이스 인증용 Provider
     *
     * @return
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailService);
        return authenticationProvider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/user/**").permitAll()
                .antMatchers("/api/**").hasRole("USER")
                .and()
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

**RequestFilter**

```java
package com.cookub.backend.filter;

import com.cookub.backend.auth.UserDetailService;
import com.cookub.backend.util.JwtUtil;
import com.cookub.backend.util.ResultCode;
import com.cookub.backend.util.ResultJson;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final UserDetailService userDetailService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        System.out.println("JwtRequestFilter 에서 Path 값 :"+path);
        //아래 경로는 이 필터가 적용되지 않는다.
        if (path.startsWith("/user")) {
            System.out.println("1. user 경로 필터 적용 안하고 들어옴");
            filterChain.doFilter(request, response);
            return;
        }
        System.out.println("Authorization Header 점검::::");
        final String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String token = null;
        HttpSession session = request.getSession();

        //Header에서 Bearer 부분 이하로 붙은 token을 파싱한다.
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
        }
        username = jwtUtil.extractUsername(token);
        if (username == null) {
            exceptionCall(response, "invalidToken");
            return;
        }
        UserDetails userDetails = userDetailService.loadUserByUsername(username);
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                    = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            session.setAttribute("email", username);
        }

        filterChain.doFilter(request, response);
    }

    private HttpServletResponse exceptionCall(HttpServletResponse response, String errorType) throws IOException {
        ResultJson resultJson = new ResultJson();
        if (errorType.equals("invalidToken")) {
            resultJson.setCode(ResultCode.INVALID_TOKEN.getCode());
            resultJson.setMsg(ResultCode.INVALID_TOKEN.getMsg());
        }

        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(objectMapper.writeValueAsString(resultJson));
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json");
        return response;
    }
}

```

## What I regreted

```plain
  코드는 작성하고 흐름은 읽엇는데 다시 한
```

## To Do List (Tomorrow)

- JWT, Security Code 정리
- TDD 양식 정리하기
- Validation
- backend branch 만들어서 준기님이랑 같이 작업하기

## Summary

> JWT+Spring Security+REST API
