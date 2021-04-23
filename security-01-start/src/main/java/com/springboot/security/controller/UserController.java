package com.springboot.security.controller;

import com.springboot.security.entity.User;
import com.springboot.security.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * @author zhangtengfei
 * @date 2021/4/22 19:36
 */

@RestController
public class UserController {
    
    @Resource
    private UserService userService;
    
    @PostMapping("/user/insert")
    public String insertUser(@RequestBody User user) {
        userService.save(user);
        return "success";
    }
}
