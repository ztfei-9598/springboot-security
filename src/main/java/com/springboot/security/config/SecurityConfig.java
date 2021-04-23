package com.springboot.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springboot.security.service.MyUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.annotation.Resource;
import java.io.PrintWriter;

/**
 * @author zhangtengfei
 * @date 2021/4/20 15:49
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Resource
    private MyUserDetailsService userDetailsService;
    
    /**
     * -------------------------------------- 1、简单案例。 设置 用户名、密码，不使用 security 自带的生成密码方式。 --------------------------------------
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        // 目前的案例还比较简单，暂时先不给密码进行加密，所以返回 NoOpPasswordEncoder 的实例即可
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * -------------------------------------------------- 将用户设置到数据库中 --------------------------------------------------
     * 
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    /**
     * -------------------------------------------------- 将用户设置到内存中 方法一 --------------------------------------------------
     * 方法二： 通过 Java 代码，将 用户名、密码 配置在内存中
     * <p>
     * 方法一：也可以直接设置到 yml 文件中
     *
     * @param auth
     * @throws Exception
     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//                /**
//                 * 现在还没有连接数据库，所以测试用户还是基于内存来配置
//                 * inMemoryAuthentication 开启在内存中定义用户。 在内存中配置了两个用户
//                 */
//                .inMemoryAuthentication()
//                .withUser("root").password("root").roles("admin")
//                // and 符号相当于就是 XML 标签的结束符，表示结束当前标签。这是个时候上下文会回到 inMemoryAuthentication 方法中，然后开启新用户的配置
//                .and()
//                .withUser("静、水无痕").password("123").roles("user");
//    }

    /**
     * -------------------------------------------------- 将用户设置到内存中 方法二 *************** 与上面方法只能共存一个 *************** --------------------------------------------------
     * <p>
     * 由于 Spring Security 支持多种数据源，例如内存、数据库、LDAP 等，这些不同来源的数据被共同封装成了一个 UserDetailService 接口，任何实现了该接口的对象都可以作为认证数据源。
     * <p>
     * 因此我们还可以通过重写 WebSecurityConfigurerAdapter 中的 userDetailsService 方法来提供一个 UserDetailService 实例进而配置多个用户
     */
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withUsername("javaboy").password("123").roles("admin").build());
//        return manager;
//    }

    /**
     * -------------------------------------- 2、继续添加配置。 --------------------------------------
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        // 用来配置忽略掉的 URL 地址，一般对于静态文件，我们可以采用此操作
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    /**
     * 在 Spring Security 中，如果我们不做任何配置，默认的登录页面和登录接口的地址都是 /login，也就是说，默认会存在如下两个请求：
     * GET http://localhost:8080/login
     * POST http://localhost:8080/login
     * 如果是 GET 请求表示你想访问登录页面，如果是 POST 请求，表示你想提交登录数据。
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                /**
                 * 1、/hello 是任何人都可以访问的接口
                 * 2、/admin/hello 是具有 admin 身份的人才能访问的接口
                 * 3、/user/hello 是具有 user 身份的人才能访问的接口
                 * 4、所有 user 能够访问的资源，admin 都能够访问
                 *
                 * 一、 Ant 风格的路径匹配符
                 *      **	匹配多层路径
                 *      *	匹配一层路径
                 *      ?	匹配任意单个字符
                 *
                 * 二、拦截规则的配置类 AbstractRequestMatcherRegistry
                 *      在任何拦截规则之前（包括 anyRequest 自身），都会先判断 anyRequest 是否已经配置，如果已经配置，则会抛出异常，系统启动失败
                 */
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                /**
                 * 剩余的其他格式的请求路径，只需要认证（登录）后就可以访问
                 */
                .anyRequest().authenticated()
                // and 方法表示结束当前标签，上下文回到HttpSecurity，开启新一轮的配置
                .and()
                /**
                 * 1、定义登录页面、登录接口。
                 *      当我们定义了登录页面为 /login.html 的时候，Spring Security 也会帮我们自动注册一个 /login.html 的接口，这个接口是 POST 请求，用来处理登录逻辑
                 * 默认的 loginPage 为 /login：
                 *     form 表单的相关配置在 FormLoginConfigurer 中， 继承了AbstractAuthenticationFilterConfigurer， 该类构造方法： setLoginPage("/login")
                 *     FormLoginConfigurer 的初始化方法 init 方法中，如果用户没有给 loginProcessingUrl 设置值的话，默认就使用 loginPage 作为 loginProcessingUrl
                 */
                .formLogin()
                // 登录页面
                .loginPage("/login.html")
                // 指定登录接口 - 要同步修改 login.html 页面中的表单项 <form action="/doLogin" method="post">
//                .loginProcessingUrl("/doLogin")
                /**
                 * 2、登录参数
                 * 2.1 登录表单中的参数是 username 和 password，注意，默认情况下，这个不能变
                 *      <form action="/login.html" method="post">
                 *          <input type="text" name="username" id="name">
                 *          <input type="password" name="password" id="pass">
                 *      </form>
                 *      FormLoginConfigurer 构造方法：
                 *              设置 username、password ： usernameParameter("username"); passwordParameter("password");
                 *              取出 username、password ： UsernamePasswordAuthenticationFilter, obtainUsername(request), obtainPassword(request)
                 *
                 * 2.2 username、password 也可以自己定义名称，同步修改 login.html 页面中的表单项
                 *      <form action="/login.html" method="post">
                 *          <input type="text" name="name" id="name">
                 *          <input type="password" name="passwd" id="pass">
                 *      </form>
                 */
//                .usernameParameter("name")
//                .passwordParameter("passwd")
                /**
                 * 3、登录成功回调
                 * 3.1 defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse)
                 *      3.1.1 alwaysUse：false
                 *              defaultSuccessUrl 中指定登录成功的跳转页面为 /index，此时分两种情况：
                 *                  - 如果你是直接在浏览器中输入的登录地址，登录成功后，就直接跳转到 /index，
                 *                  - 如果你是在浏览器中输入了其他地址，例如 http://localhost:8080/hello，结果因为没有登录，又重定向到登录页面，此时登录成功后，就不会来到 /index ，而是来到 /hello 页面
                 *      3.1.2 alwaysUse：true
                 *              defaultSuccessUrl 的效果和 successForwardUrl 一致
                 *
                 * 3.2 successForwardUrl(String forwardUrl)
                 *      不管你是从哪里来的，登录后一律跳转到 successForwardUrl 指定的地址
                 *
                 * 3.3 实际操作中，defaultSuccessUrl 和 successForwardUrl 只需要配置一个即可
                 * 3.4 这两个配置跳转地址的，适用于前后端不分的开发！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
                 *     必杀技：successHandler
                 */
//                .defaultSuccessUrl("/index")
//                .successForwardUrl("/index")
                /**
                 * 3、登录成功 - 前后端分离情形：
                 *      登录成功了，服务端就返回一段登录成功的提示 JSON 给前端，前端收到之后，该跳转该展示，由前端自己决定，就和后端没有关系了
                 * AuthenticationSuccessHandler
                 *     onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
                 *          HttpServletRequest 我们可以做服务端跳转，
                 *          HttpServletResponse 我们可以做客户端跳转，当然，也可以返回 JSON 数据。
                 *          Authentication 参数则保存了我们刚刚登录成功的用户信息
                 * 返回结果示例：
                 * {
                 * password: null,
                 * username: "javaBoy",
                 * authorities: [
                 *      {
                 *      authority: "ROLE_admin"
                 *      }
                 * ],
                 * accountNonExpired: true,
                 * accountNonLocked: true,
                 * credentialsNonExpired: true,
                 * enabled: true
                 * }
                 */
                .successHandler((req, resp, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(new ObjectMapper().writeValueAsString(principal));
                    out.flush();
                    out.close();
                })
                /**
                 * 4、登录失败回调
                 * failureForwardUrl 是登录失败之后会发生服务端跳转，
                 * failureUrl 则在登录失败之后，会发生重定向。
                 * 「这两个方法在设置的时候也是设置一个即可」。
                 */
//                .failureUrl("/fail")
                /**
                 * 4、登录失败 - 前后端分离使用
                 * 4.1 onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,AuthenticationException exception) 
                 *          Exception 中则保存了登录失败的原因，我们可以将之通过 JSON 返回到前端。
                 *
                 * 4.2 根据不同的异常类型，我们可以给用户一个更加明确的提示
                 * resp.setContentType("application/json;charset=utf-8");
                 * PrintWriter out = resp.getWriter();
                 * RespBean respBean = RespBean.error(e.getMessage());
                 * if (e instanceof LockedException) {
                 *     respBean.setMsg("账户被锁定，请联系管理员!");
                 * } elseif (e instanceof CredentialsExpiredException) {
                 *     respBean.setMsg("密码过期，请联系管理员!");
                 * } elseif (e instanceof AccountExpiredException) {
                 *     respBean.setMsg("账户过期，请联系管理员!");
                 * } elseif (e instanceof DisabledException) {
                 *     respBean.setMsg("账户被禁用，请联系管理员!");
                 * } elseif (e instanceof BadCredentialsException) {
                 *     respBean.setMsg("用户名或者密码输入错误，请重新输入!");
                 * }
                 * out.write(new ObjectMapper().writeValueAsString(respBean));
                 * out.flush();
                 * out.close();
                 *
                 * 4.3
                 * 当用户登录时，用户名或者密码输入错误，我们一般只给一个模糊的提示，即「用户名或者密码输入错误，请重新输入」，
                 * 而不会给一个明确的诸如“用户名输入错误”或“密码输入错误”这样精确的提示
                 *
                 */
                .failureHandler((req, resp, e) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("登录失败： " + e.getMessage());
                    out.flush();
                    out.close();
                })
                // permitAll 表示登录相关的页面/接口不要被拦截。
                .permitAll()
                /**
                 * 5、注销登录
                 */
                .and()
                .logout()
                // 默认注销的 URL 是 /logout，是一个 GET 请求，我们可以通过 logoutUrl 方法来修改默认的注销 URL
                .logoutUrl("/logout")
                // 可以修改注销 URL，还可以修改请求方式，实际项目中，这个方法和 logoutUrl 任意设置一个即可
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
                // 注销成功后要跳转的页面
                .logoutSuccessUrl("/index")
                /**
                 * 5、注销登录  前后端分离方案 返回json
                 */
//                .logoutSuccessHandler((req, resp, authentication) -> {
//                    resp.setContentType("application/json;charset=utf-8");
//                    PrintWriter out = resp.getWriter();
//                    out.write("注销成功");
//                    out.flush();
//                    out.close();
//                })
                // 清除 cookie
                .deleteCookies()
                // clearAuthentication 和 invalidateHttpSession 分别表示清除认证信息和使 HttpSession 失效，默认可以不用配置，默认就会清除
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
                .and()
        /**
         * 6、未认证处理方案
         *
         * 没有认证就访问数据，直接重定向到登录页面就行了，这没错，系统默认的行为也是这样。
         * 在前后端分离中，这个逻辑明显是有问题的，如果用户没有登录就访问一个需要认证后才能访问的页面，
         * 这个时候，我们不应该让用户重定向到登录页面，而是给用户一个尚未登录的提示，前端收到提示之后，再自行决定页面跳转
         *
         * AuthenticationEntryPoint ，该接口有一个实现类：LoginUrlAuthenticationEntryPoint ，该类中有一个方法 commence
         * commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
         * 这个方法是用来决定到底是要重定向还是要 forward，通过 Debug 追踪，我们发现默认情况下 useForward 的值为 false，所以请求走进了重定向
         * 直接重写这个方法，在方法中返回 JSON 即可，不再做重定向操作
         */
//                .exceptionHandling()
//                .authenticationEntryPoint((req, resp, authException) -> {
//                            resp.setContentType("application/json;charset=utf-8");
//                            PrintWriter out = resp.getWriter();
//                            out.write("尚未登录，请先登录");
//                            out.flush();
//                            out.close();
//                        }
//                )
        ;
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
