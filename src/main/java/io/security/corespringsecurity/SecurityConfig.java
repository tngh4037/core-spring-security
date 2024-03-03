package io.security.corespringsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

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
        ;
    }
}
