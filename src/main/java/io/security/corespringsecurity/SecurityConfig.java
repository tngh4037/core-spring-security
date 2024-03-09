package io.security.corespringsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

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
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http
                .formLogin();
    }
}
