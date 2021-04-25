package com.springboot.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 测试流程：
 * 用户首先访问 csrf 项目中的接口，在访问的时候需要登录，用户就执行了登录操作，访问完后，用户并没有执行登出操作；
 * 然后用户访问 csrf-danger 中的页面，看到了超链接，好奇这美女到底长啥样，一点击，结果钱就被人转走了
 * 
 * 这就相当于 在一个域名中(localhost:8081)访问了另一个域名中的数据(localhost:8080)
 * 
 * @author zhangtengfei
 * @date 2021/4/20 15:49
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .csrf()
                // Spring Security 中默认是可以自动防御 CSRF 攻击的，所以我们要把这个关闭掉
                .disable();
    }
}
