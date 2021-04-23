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
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.annotation.Resource;
import javax.sql.DataSource;
import java.io.PrintWriter;

/**
 * @author zhangtengfei
 * @date 2021/4/20 15:49
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyUserDetailsService userDetailsService;
    
    @Resource
    DataSource dataSource;

    /**
     * ----------------- 持久化令牌 -----------------
     * 
     * 保存令牌的处理类则是 PersistentRememberMeToken
     * 需要一张表来记录令牌信息，这张表我们可以完全自定义，也可以使用系统默认提供的 JDBC 来操作，如果使用默认的 JDBC，即 JdbcTokenRepositoryImpl
     * 
     * @return
     */
    @Bean
    JdbcTokenRepositoryImpl jdbcTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }
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
//                .antMatchers("/admin/**").hasRole("admin")
//                .antMatchers("/user/**").hasRole("user")
                /**
                 * 持久化令牌的方式依然存在用户身份被盗用的问题
                 * 另一种方案，就是二次校验。
                 * 为了让用户使用方便，我们开通了自动登录功能，但是自动登录功能又带来了安全风险，
                 * 一个规避的办法就是如果用户使用了自动登录功能，我们可以只让他做一些常规的不敏感操作，
                 * 例如数据浏览、查看，但是不允许他做任何修改、删除操作，如果用户点击了修改、删除按钮，我们可以跳转回登录页面，让用户重新输入密码确认身份，然后再允许他执行敏感操作
                 */
                //  /rememberme 接口，必须是通过自动登录认证后才能访问，如果用户是通过用户名/密码认证的，则无法访问该接口
                .antMatchers("/rememberme").rememberMe()
                //  /admin 接口，必须要用户名密码认证之后才能访问，如果用户是通过自动登录认证的，则必须重新输入用户名密码才能访问该接口
                .antMatchers("/admin/**").fullyAuthenticated()
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
//                .loginPage("/login.html")
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
                .and()
                /**
                 * 用户在登录成功后，在某一段时间内，如果用户关闭了浏览器并重新打开，或者服务器重启了，都不需要用户重新登录了，用户依然可以直接访问接口数据
                 * 关闭浏览器，再重新打开浏览器。正常情况下，浏览器关闭再重新打开，如果需要再次访问 hello 接口，就需要我们重新登录了。
                 * 但是此时，我们再去访问 hello 接口，发现不用重新登录了，直接就能访问到，这就说明我们的 RememberMe 配置生效了
                 *
                 *  cookie 中多出来的这个 remember-me: YWRtaW46MTYyMDM2NjIyNzQyMjoyMTZjNjE2ZmU0NGRmNmM3OGI0ZjY3ZDU3NTFlYjFhMQ
                 *  Base64 解码后得到字符串
                 *  admin:1620366227422:216c616fe44df6c78b4f67d5751eb1a1
                 * 第一段是用户名，这个无需质疑。
                 * 第二段看起来是一个时间戳，我们通过在线工具或者 Java 代码解析后发现，这是一个两周后的数据。
                 * 第三段我就不卖关子了，这是使用 MD5 散列函数算出来的值，
                 * 他的明文格式是 username + ":" + tokenExpiryTime + ":" + password + ":" + key，最后的 key 是一个散列盐值，可以用来防治令牌被修改。
                 *
                 * 如果我们没有自己去设置这个 key，默认是在 RememberMeConfigurer#getKey 方法中进行设置的，它的值是一个 UUID 字符串。
                 * 
                 * 流程：
                 * 在浏览器关闭后，并重新打开之后，用户再去访问 hello 接口，此时会携带着 cookie 中的 remember-me 到服务端，
                 * 服务到拿到值之后，可以方便的计算出用户名和过期时间，再根据用户名查询到用户密码，然后通过 MD5 散列函数计算出散列值，
                 * 再将计算出的散列值和浏览器传递来的散列值进行对比，就能确认这个令牌是否有效。
                 * 
                 * 生成的核心:
                 * TokenBasedRememberMeServices#onLoginSuccess
                 * 
                 * 解析：用户关掉并打开浏览器之后，重新访问 /hello 接口，此时的认证流程又是怎么样的？？
                 * Spring Security 中的一系列功能都是通过一个过滤器链实现的，RememberMe 这个功能当然也不例外 ： RememberMeAuthenticationFilter doFilter()
                 * - 如果从 SecurityContextHolder 中无法获取到当前登录用户实例，那么就调用 rememberMeServices.autoLogin 逻辑进行登录
                 * - 提取出 cookie 信息，并对 cookie 信息进行解码，解码之后，再调用 processAutoLoginCookie 方法去做校验
                 */
                .rememberMe()
                /**
                 * key 默认值是一个 UUID 字符串，这样会带来一个问题，就是如果服务端重启，这个 key 会变，这样就导致之前派发出去的所有 remember-me 自动登录令牌失效，所以，我们可以指定这个 key
                 */
                .key("spring-security")
                /**
                 * 持久化令牌
                 * 
                 * 生成令牌/解析令牌的实现类变了  这次的实现类主要是：PersistentTokenBasedRememberMeServices
                 * 令牌生成：onLoginSuccess
                 *      1.在登录成功后，首先还是获取到用户名，即 username。
                 *      2.接下来构造一个 PersistentRememberMeToken 实例，generateSeriesData 和 generateTokenData 方法分别用来获取 series 和 token，具体的生成过程实际上就是调用 SecureRandom 生成随机数再进行 Base64 编码，不同于我们以前用的 Math.random 或者 java.util.Random 这种伪随机数，SecureRandom 则采用的是类似于密码学的随机数生成规则，其输出结果较难预测，适合在登录这样的场景下使用。
                 *      3.调用 tokenRepository 实例中的 createNewToken 方法，tokenRepository 实际上就是我们一开始配置的 JdbcTokenRepositoryImpl，所以这行代码实际上就是将 PersistentRememberMeToken 存入数据库中。
                 *      4.最后 addCookie，大家可以看到，就是添加了 series 和 token
                 * 令牌解析：processAutoLoginCookie
                 *      1.首先从前端传来的 cookie 中解析出 series 和 token。
                 *      2.根据 series 从数据库中查询出一个 PersistentRememberMeToken 实例。
                 *      3.如果查出来的 token 和前端传来的 token 不相同，说明账号可能被人盗用（别人用你的令牌登录之后，token 会变）。此时根据用户名移除相关的 token，相当于必须要重新输入用户名密码登录才能获取新的自动登录权限。
                 *      4.接下来校验 token 是否过期。
                 *      5.构造新的 PersistentRememberMeToken 对象，并且更新数据库中的 token（这就是我们文章开头说的，新的会话都会对应一个新的 token）。
                 *      6.将新的令牌重新添加到 cookie 中返回。
                 *      7.根据用户名查询用户信息，再走一波登录流程
                 */
                .tokenRepository(jdbcTokenRepository())
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
