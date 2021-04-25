package com.springboot.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @author zhangtengfei
 * @date 2021/4/25 16:46
 */

@Service
public class HelloService {
    /**
     * 只有当前登录用户名为 user 的用户才可以访问该方法
     */
    @PreAuthorize("principal.username.equals('user')")
    public String hello() {
        return "hello";
    }

    /**
     * 该方法的用户必须具备 admin 角色
     */
    @PreAuthorize("hasRole('admin')")
    public String admin() {
        return "admin";
    }

    /**
     * 该方法的用户必须具备 user 角色
     */
    @Secured({"ROLE_user"})
    public String user() {
        return "user";
    }

    /**
     * 访问该方法的 age 参数必须大于 10
     */
    @PreAuthorize("#age>10")
    public String getAge(Integer age) {
        return String.valueOf(age);
    }

    /**
     * ---------------------------------- 使用过滤注解 ----------------------------------
     * 集合进行过滤，只返回后缀为 2 的元素
     *
     * @return [ "javaboy:2" ]
     */
    @PostFilter("filterObject.lastIndexOf('2')!=-1")
    public List<String> getAllUser() {
        List<String> users = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            users.add("javaboy:" + i);
        }
        return users;
    }

    /**
     * 由于有两个集合，因此使用 filterTarget 指定过滤对象
     * 
     * @param ages
     * @param users
     */
    @PreFilter(filterTarget = "ages", value = "filterObject%2==0")
    public void getAllAge(List<Integer> ages, List<String> users) {
        System.out.println("ages = " + ages);
        System.out.println("users = " + users);
    }
}
