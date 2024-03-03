package io.security.corespringsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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
                .authorizeRequests()
                .anyRequest().authenticated();
        // 인증 정책
        http
                .formLogin();
        // 로그아웃 정책
        http
                .logout() // 이하의 코드가 로그아웃에 관한 설정임을 명시
                .logoutUrl("/logout") // 로그아웃 요청 POST url (default: /logout)
                .logoutSuccessUrl("/login") // 로그아웃 성공 시 이동할 url
                .addLogoutHandler(new LogoutHandler() { // 로그아웃 처리 핸들러
                    @Override
                    public void logout(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 시 핸들러
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication) throws IOException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me"); // 로그아웃 후 쿠키 삭제
    }
}
