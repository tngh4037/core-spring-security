package io.security.corespringsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

@Configuration
@EnableWebSecurity // 웹 보안을 활성화 하기 위한 annotation
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * (인증 / 인가) API를 추가적으로 설정할 수 있는 configure 메서드를 오버라이딩한다.
     * 그러면 configure 메서드 에서 설정한 API 설정 정보로 웹 보안이 활성화 된다.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        http
                .authorizeRequests() // authorizeRequests()는 ExpressionInterceptUrlRegistry 객체를 반환한다.
                                     // 이 객체를 사용하면 URL 경로와 패턴 및 해당 경로의 보안 요구사항을 구성할 수 있다.
                .anyRequest().authenticated(); // 모든 요청에 대해서 인증을 받도록 한다.

        // 인증 정책
        http
                .formLogin() // 인증 방식은 form 로그인 방식으로 한다.
                .loginPage("/loginPage") // 직접 제공할 로그인 페이지로 이동할 url을 작성한다. ( 작성하지 않으면, 스프링 시큐리티에서 기본으로 제공하는 로그인 페이지를 사용한다. ) ( default : /login )
                .defaultSuccessUrl("/") // 인증에 성공한 후 이동할 url 정보를 줄 수 있다.
                .failureUrl("/login") // 인증에 실패한 경우 이동할 url 정보를 줄 수 있다.
                .usernameParameter("userId") // 필드명을 변경할 수 있다. (로그인 페이지를 우리가 별도로 만드는 경우, 화면 태그의 name에도 맞춰줘야 한다.) ( default : username )
                .passwordParameter("passwd") // 필드명을 변경할 수 있다. (로그인 페이지를 우리가 별도로 만드는 경우, 화면 태그의 name에도 맞춰줘야 한다.) ( default : password )
                .loginProcessingUrl("/login_proc") // 폼 태그의 action url이다. (그러면 화면 태그와도 맞춰줘야 한다.) ( default : /login )
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                                        HttpServletResponse httpServletResponse,
                                                        Authentication authentication) throws IOException, ServletException { // Authentication authentication: 인증 성공시 최종적으로 인증한 결과인 인증 객체 정보를 파라미터로 받을 수 있다.
                        System.out.println("authentication :: " + authentication.getName()); // 현재 인증에 성공한 사용자 name
                        httpServletResponse.sendRedirect("/"); // 인증에 성공하면 루트 페이지(/)로 이동한다.
                    }
                }) // 로그인 성공시 호출할 클래스를 작성할 수 있다. (AuthenticationSuccessHandler 인터페이스를 구현한 구현체를 여기에 넣어주면 된다. 여기서는 간단하게 익명 클래스를 사용했다.)
                .failureHandler(new AuthenticationFailureHandler() {
                     @Override
                     public void onAuthenticationFailure(HttpServletRequest httpServletRequest,
                                                         HttpServletResponse httpServletResponse,
                                                         AuthenticationException e) throws IOException, ServletException {  // AuthenticationException e: 인증 예외의 객체를 파라미터로 받을 수 있다.
                         System.out.println("exception :: " + e.getMessage());
                         httpServletResponse.sendRedirect("/login"); // 인증 실패시 로그인 페이지로 이동한다.
                     }
                 })
                .permitAll() // 위 인가 정책에 의해 "/loginPage" 경로로 접근시 인증을 받아야 한다. 띠라서 이경우는 인증을 받지 않아도 되도록 누구나 접근 가능하도록 한다.
        ;

    }
}
