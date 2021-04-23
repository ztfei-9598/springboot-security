package com.springboot.security.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.extension.activerecord.Model;
import lombok.Data;

/**
 * <p>
 * 用户实体类主要需要实现  UserDetails 接口，并实现接口中的方法
 * </p>
 *
 * @author zhangtengfei
 * @since 2021-04-21
 */
@TableName("user")
@Data
public class User extends Model<User> {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    protected Integer id;

    /**
     * 用户名
     */
    protected String username;

    /**
     * 密码
     */
    protected String password;

    /**
     * 账户是否没有过期
     */
    protected boolean accountNonExpired;

    /**
     * 账户是否没有被锁定
     */
    protected boolean accountNonLocked;

    /**
     * 密码是否没有过期
     */
    protected boolean credentialsNonExpired;

    /**
     * 账户是否可用
     */
    protected boolean enabled;
}
