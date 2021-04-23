package com.springboot.security.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.springboot.security.entity.MyUserDetail;
import com.springboot.security.entity.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * @author zhangtengfei
 * @date 2021/4/22 19:30
 */

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Resource
    private UserService userService;

    /**
     * 根据用户名去查询用户信息（查出来之后，系统会自动进行密码比对）
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.lambda().eq(User::getUsername, username);
        MyUserDetail user = (MyUserDetail) userService.getOne(queryWrapper);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在！");
        }
        return user;
    }
}
