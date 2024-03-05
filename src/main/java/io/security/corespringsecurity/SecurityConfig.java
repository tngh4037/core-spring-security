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
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin();
        http
                .sessionManagement()
                .sessionFixation().changeSessionId();
    }
}
