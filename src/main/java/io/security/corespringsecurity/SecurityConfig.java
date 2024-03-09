package io.security.corespringsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity // 웹 보안을 활성화 하기 위한 annotation
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * configure(AuthenticationManagerBuilder auth)
     * - AuthenticationManagerBuilder를 통해서 사용자를 생성하고, 권한을 설정할 수 있도록 제공한다. ( 메모리 기반으로 사용자 생성 )
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    /**
     * (인증 / 인가) API를 추가적으로 설정할 수 있는 configure 메서드를 오버라이딩한다.
     * 그러면 configure 메서드 에서 설정한 API 설정 정보로 웹 보안이 활성화 된다.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request,
                                                        HttpServletResponse response,
                                                        Authentication authentication) throws IOException, ServletException {
                        // (인증에 성공한 다음) ExceptionTranslationFilter 에서 저장한 이전 요청 정보를 꺼내서, 사용자가 원래 가고자 했던 경로로 이동
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = "/";
                        if (savedRequest != null) {
                            redirectUrl = savedRequest.getRedirectUrl();
                        }
                        response.sendRedirect(redirectUrl);
                    }
                });
        http
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {  // 인증 예외 발생시 처리
                    @Override
                    public void commence(HttpServletRequest request,
                                         HttpServletResponse response,
                                         AuthenticationException e) throws IOException, ServletException {
                        response.sendRedirect("/login"); // 이렇게하면 스프링 시큐리티가 제공해주는 기본 로그인 페이지가 아닌, 애플리케이션에 정의된 /login을 호출한다.
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() {  // 인가 예외 발생시 처리
                    @Override
                    public void handle(HttpServletRequest request,
                                       HttpServletResponse response,
                                       AccessDeniedException e) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });
    }
}
