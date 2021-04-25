package com.springboot.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author zhangtengfei
 * @date 2021/4/20 15:29
 * 
 * 注：@restController不能跳转到thymeleaf中的hello.html页面！！！！
 */
@Controller
public class HelloController {

    /**
     * 假设 /transfer 是一个转账接口
     *
     * @param name
     * @param money
     */
    @PostMapping("/transfer")
    public void transferMoney(String name, Integer money) {
        System.out.println("name = " + name);
        System.out.println("money = " + money);
    }

    @GetMapping("/hello")
    public String hello() {
        // 这样路由就映射到 hello.html 了
        return "hello";
    }

    /**
     * 这个测试接口是一个 POST 请求，因为默认情况下，GET、HEAD、TRACE 以及 OPTIONS 是不需要验证 CSRF 攻击的。
     *
     * @return
     */
    @PostMapping("/hello")
    @ResponseBody
    public String csrf() {
        return "csrf hello";
    }
}
