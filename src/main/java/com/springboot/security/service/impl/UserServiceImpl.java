package com.springboot.security.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.springboot.security.entity.Role;
import com.springboot.security.entity.User;
import com.springboot.security.mapper.UserMapper;
import com.springboot.security.service.UserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Set;

/**
 * <p>
 * 服务实现类
 * </p>
 *
 * @author zhangtengfei
 * @since 2021-04-21
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

    @Resource
    private UserMapper userMapper;

    @Override
    public Set<Role> getUserRole(String username) {
        return userMapper.getUserRole(username);
    }
}
