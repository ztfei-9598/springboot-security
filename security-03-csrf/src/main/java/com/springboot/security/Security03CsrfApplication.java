package com.springboot.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Security03CsrfApplication {

    public static void main(String[] args) {
        SpringApplication.run(Security03CsrfApplication.class, args);
    }

    /**
     * --------------------------------- CSRF 防御源码 ---------------------------------
     * 1、CsrfToken  保存 csrf 参数的规范。  
     * CsrfToken ---> 默认实现类： DefaultCsrfToken
     * 前两个方法是获取 _csrf 参数的 key，第三个是获取 _csrf 参数的 value
     * 2、CsrfTokenRepository 类
     * CsrfToken 相当于就是 _csrf 参数的载体。那么参数是如何生成和保存？ 
     * CsrfTokenRepository ---> 实现类：HttpSessionCsrfTokenRepository（默认方案）   CookieCsrfTokenRepository
     *      - saveToken 方法将 CsrfToken 保存在 HttpSession 中，将来再从 HttpSession 中取出和前端传来的参数做比较
     *      - loadToken 方法当然就是从 HttpSession 中读取 CsrfToken 出来
     *      - generateToken 是生成 CsrfToken 的过程，默认载体就是 DefaultCsrfToken，而 CsrfToken 的值是一个 UUID 字符串。
     *        DefaultCsrfToken 是还有两个参数 headerName 和 parameterName，这两个参数是前端保存参数的 key
     * 这是默认的方案，适用于前后端不分离的开发
     * 3、前后端分离方案 CookieCsrfTokenRepository 
     * 和 HttpSessionCsrfTokenRepository 相比，这里 _csrf 数据保存的时候，都保存到 cookie 中去了，
     * 当然读取的时候，也是从 cookie 中读取，其他地方则和 HttpSessionCsrfTokenRepository 是一样的
     * 4、参数校验  CsrfFilter 过滤器实现  doFilterInternal 
     *      - 首先调用 tokenRepository.loadToken 方法读取 CsrfToken 出来
     *      - 如果调用 tokenRepository.loadToken 方法没有加载到 CsrfToken，那说明这个请求可能是第一次发起，
     *        则调用 tokenRepository.generateToken 方法生成 CsrfToken ，并调用 tokenRepository.saveToken 方法保存 CsrfToken。
     *      - 大家注意，这里还调用 request.setAttribute 方法存了一些值进去，这就是默认情况下，我们通过 jsp 或者 thymeleaf 标签渲染 _csrf 的数据来源。
     *      - requireCsrfProtectionMatcher.matches 方法则使用用来判断哪些请求方法需要做校验，默认情况下，"GET", "HEAD", "TRACE", "OPTIONS" 方法是不需要校验的。
     *      - 接下来获取请求中传递来的 CSRF 参数，先从请求头中获取，获取不到再从请求参数中获取。
     *      - 获取到请求传来的 csrf 参数之后，再和一开始加载到的 csrfToken 做比较，如果不同的话，就抛出异常。
     */
}
