package com.springboot.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springboot.security.provider.MyAuthenticationProvider;
import com.springboot.security.service.MyUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.Resource;
import java.io.PrintWriter;
import java.util.Arrays;

/**
 * 自定义认证思路：
 * <p>
 * 1.AuthenticationProvider -> Authentication
 * 每一个 Authentication 都有适合它的 AuthenticationProvider 去处理校验。
 * 例如处理 UsernamePasswordAuthenticationToken 的 AuthenticationProvider 是 DaoAuthenticationProvider
 * AuthenticationProvider 中看到一个 supports 方法，就是用来判断 AuthenticationProvider 是否支持当前 Authentication
 * <p>
 * 2.DaoAuthenticationProvider(在这里 校验用户、密码 的) ---父类---> AbstractUserDetailsAuthenticationProvider
 * <p>
 * 3.AuthenticationProvider 都是通过 ProviderManager#authenticate 方法来调用的
 * <p>
 * 4.改进思路
 * 登录请求是调用 AbstractUserDetailsAuthenticationProvider#authenticate 方法进行认证的，在该方法中，
 * 又会调用到 DaoAuthenticationProvider#additionalAuthenticationChecks 方法做进一步的校验，去校验用户登录密码。
 * 我们可以自定义一个 AuthenticationProvider 代替 DaoAuthenticationProvider，并重写它里边的 additionalAuthenticationChecks 方法，
 * 在重写的过程中，加入验证码的校验逻辑即可。
 * <p>
 * 这样既不破坏原有的过滤器链，又实现了自定义认证功能。「常见的手机号码动态登录，也可以使用这种方式来认证。」
 *
 * @author zhangtengfei
 * @date 2021/4/20 15:49
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyUserDetailsService userDetailsService;

    @Resource
    private MyWebAuthenticationDetailsSource myWebAuthenticationDetailsSource;
    
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    MyAuthenticationProvider myAuthenticationProvider() {
        MyAuthenticationProvider myAuthenticationProvider = new MyAuthenticationProvider();
        myAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        myAuthenticationProvider.setUserDetailsService(userDetailsService);
        return myAuthenticationProvider;
    }

    /**
     * 所有的 AuthenticationProvider 都是放在 ProviderManager 中统一管理的，
     * 所以接下来我们就要自己提供 ProviderManager，然后注入自定义的 MyAuthenticationProvider
     * 
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        ProviderManager manager = new ProviderManager(Arrays.asList(myAuthenticationProvider()));
        return manager;
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/vc.jpg").permitAll()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated()
                .and()
                /**
                 * 登录
                 */
                .formLogin()
                .authenticationDetailsSource(myWebAuthenticationDetailsSource)
                .successHandler((req, resp, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(new ObjectMapper().writeValueAsString(principal));
                    out.flush();
                    out.close();
                })
                .failureHandler((req, resp, e) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("登录失败： " + e.getMessage());
                    out.flush();
                    out.close();
                })
                .permitAll()
                /**
                 * 注销登录
                 */
                .and()
                .logout().logoutUrl("/logout").logoutSuccessUrl("/index")
                // 清除 cookie
                .deleteCookies();
    }

    /**
     * 角色继承
     * 所有 user 能够访问的资源，admin 都能够访问
     *
     * @return
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return hierarchy;
    }
}
