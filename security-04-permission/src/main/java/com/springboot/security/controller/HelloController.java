package com.springboot.security.controller;

import com.springboot.security.service.HelloService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * @author zhangtengfei
 * @date 2021/4/20 15:29
 */
@RestController
public class HelloController {
    @Autowired
    HelloService helloService;

    /**
     * 只有当前登录用户名为 user 的用户才可以访问该方法
     */
    @GetMapping("/hello")
    public String hello() {
        return helloService.hello();
    }

    @GetMapping("/admin/hello")
    public String admin() {
        return helloService.admin();
    }

    @GetMapping("/user/hello")
    public String user() {
        return helloService.user();
    }

    /**
     * 访问该方法的 age 参数必须大于 98
     */
    @GetMapping("/age")
    public String getAge(@RequestParam Integer age) {
        return helloService.getAge(age);
    }

    /**
     * 集合进行过滤，只返回后缀为 2 的元素
     *
     * @return
     */
    @GetMapping("/users")
    public List<String> getAllUsers() {
        return helloService.getAllUser();
    }

    @GetMapping("/ages")
    public void getAllAges() {
        List<Integer> ages = new ArrayList<>();
        ages.add(98);
        ages.add(99);
        ages.add(100);
        List<String> users = new ArrayList<>();
        users.add("javaboy");
        users.add("江南一点雨");
        /**
         * ages = [98, 100]
         * users = [javaboy, 江南一点雨]
         */
        helloService.getAllAge(ages, users);
    }
}