package com.springboot.security.service;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.springboot.security.domain.MyUserDetail;
import com.springboot.security.entity.Role;
import com.springboot.security.entity.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Set;

/**
 * 这里其实就是把  之前用户密码设置到内存中的方式 转变为 设置到数据库的方式
 *
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
        // 获取user信息
        User user = userService.getOne(Wrappers.lambdaQuery(User.class).eq(User::getUsername, username));
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在！");
        }
        // 获取当前user的role信息
        Set<Role> userRole = userService.getUserRole(username);
        // 父类不能强转为子类！
        MyUserDetail userDetail = MyUserDetail.builder().roles(userRole).build();
        userDetail.setUsername(user.getUsername());
        userDetail.setPassword(user.getPassword());
        userDetail.setAccountNonExpired(user.isAccountNonExpired());
        userDetail.setAccountNonLocked(user.isAccountNonLocked());
        userDetail.setCredentialsNonExpired(user.isCredentialsNonExpired());
        userDetail.setEnabled(user.isEnabled());
        return userDetail;
    }
}
