package com.springboot.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zhangtengfei
 * @date 2021/4/20 15:29
 */
@RestController
public class HelloController {
    /**
     * 1、访问 http://localhost:8080/hello 需要输入默认密码
     * UserDetailsServiceAutoConfiguration.getOrDeducePassword()
     * 控制台打印密码： isPasswordGenerated 方法返回 true，即密码是默认生成的。SecurityProperties
     * <p>
     * 2、密码随机生成 随机生成的密码，每次启动时都会变。
     * 对登录的用户名/密码进行配置，有三种不同的方式：
     * 2.1 在 application.properties 中进行配置
     * SecurityProperties 类中 加了 @ConfigurationProperties(prefix = "spring.security")
     * 所以：
     * spring.security.user.name=javaboy
     * spring.security.user.password=123
     * 密码在注入进来之后，还顺便设置了 passwordGenerated 属性为 false，这个属性设置为 false 之后，控制台就不会打印默认的密码了
     * <p>
     * <p>
     * 2.2 通过 Java 代码配置在内存中
     * 密码加密方案：常用的散列函数有 MD5 消息摘要算法、安全散列算法（Secure Hash Algorithm）
     * 但是仅仅使用散列函数还不够，为了增加密码的安全性，一般在密码加密过程中还需要加盐，
     * 所谓的盐可以是一个随机数也可以是用户名，加盐之后，即使密码明文相同的用户生成的密码密文也不相同，这可以极大的提高密码的安全性。
     * 但是传统的加盐方式需要在数据库中有专门的字段来记录盐值，这个字段可能是用户名字段（因为用户名唯一），也可能是一个专门记录盐值的字段，这样的配置比较繁琐。
     * Spring Security 提供了多种密码加密方案，官方推荐使用 BCryptPasswordEncoder，BCryptPasswordEncoder 就自带了盐，处理起来非常方便。
     * 而 BCryptPasswordEncoder 就是 PasswordEncoder 接口的实现类
     * <p>
     * <p>
     * 2.3 通过 Java 从数据库中加载
     *
     * @return
     */
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    /**
     * 1、/hello 是任何人都可以访问的接口
     * 2、/admin/hello 是具有 admin 身份的人才能访问的接口
     * 3、/user/hello 是具有 user 身份的人才能访问的接口
     * 4、所有 user 能够访问的资源，admin 都能够访问
     *
     * @return
     */
    @GetMapping("/admin/hello")
    public String admin() {
        return "admin";
    }

    @GetMapping("/user/hello")
    public String user() {
        return "user";
    }

    @GetMapping("/rememberme")
    public String rememberme() {
        return "rememberme";
    }

}
