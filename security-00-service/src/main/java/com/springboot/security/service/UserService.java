package com.springboot.security.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.springboot.security.entity.Role;
import com.springboot.security.entity.User;

import java.util.Set;

/**
 * <p>
 * 服务类
 * </p>
 *
 * @author zhangtengfei
 * @since 2021-04-21
 */
public interface UserService extends IService<User> {

    /**
     * 获取用户角色
     *
     * @return
     */
    Set<Role> getUserRole(String username);
}
