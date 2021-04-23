package com.springboot.security.config;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * 1、spring-security 如何快速的查看登录用户的 ip 地址等信息
 * <p>
 * UsernamePasswordAuthenticationFilter -> attemptAuthentication() -> setDetails()方法: setDetails(HttpServletRequest, UsernamePasswordAuthenticationToken)
 * UsernamePasswordAuthenticationToken 在设置 details
 * <p>
 * details的值：
 * AuthenticationDetailsSource ---实现类--->  WebAuthenticationDetailsSource ---> 保存了用户登录地址和 sessionId
 * <p>
 * 2、用户登录后可以随时拿到ip
 * Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
 * WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
 * System.out.println(details);
 * <p>
 * 3、定制
 * 因为默认它只提供了 IP 和 sessionid 两个信息，如果我们想保存关于 Http 请求的更多信息，就可以通过自定义 WebAuthenticationDetails 来实现
 * 如果我们要定制 WebAuthenticationDetails，还要连同 WebAuthenticationDetailsSource 一起重新定义
 *
 * @author zhangtengfei
 * @date 2021/4/23 17:06
 */
public class MyWebAuthenticationDetails extends WebAuthenticationDetails {

    private boolean isPassed;
    
    /**
     * Records the remote address and will also set the session Id if a session already
     * exists (it won't create one).
     *
     * @param request that the authentication request was received from
     */
    public MyWebAuthenticationDetails(HttpServletRequest request) {
        // 记录 ip 及 sessionId
        super(request);
        String code = request.getParameter("code");
        String verify_code = (String) request.getSession().getAttribute("verify_code");
        if (code != null && verify_code != null && code.equals(verify_code)) {
            isPassed = true;
        }
    }

    public boolean isPassed() {
        return isPassed;
    }
}
