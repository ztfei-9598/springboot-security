package com.springboot.security.provider;

import com.springboot.security.config.MyWebAuthenticationDetails;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

/**
 
 * 所有的 AuthenticationProvider 都是放在 ProviderManager 中统一管理的，
 * 所以接下来我们就要自己提供 ProviderManager，然后注入自定义的 MyAuthenticationProvider
 *
 * @author zhangtengfei
 * @date 2021/4/23 16:08
 */
public class MyAuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
//        HttpServletRequest req = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
//        // 将请求中的认证码 与 session中的码对比
//        String code = req.getParameter("code");
//        String verify_code = (String) req.getSession().getAttribute("verify_code");
//        if (code == null || !code.equals(verify_code)) {
//            throw new AuthenticationServiceException("验证码错误");
//        }
//        // 通过 super 调用父类方法，主要做密码的校验
//        super.additionalAuthenticationChecks(userDetails, authentication);
        /**
         * security 可以自定义获取request相关的多个属性：ip、session、code(自定义参数)
         */
        if (!((MyWebAuthenticationDetails) authentication.getDetails()).isPassed()) {
            throw new AuthenticationServiceException("验证码错误");
        }
        super.additionalAuthenticationChecks(userDetails, authentication);

    }
}