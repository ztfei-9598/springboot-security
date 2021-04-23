package com.springboot.security.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.springboot.security.entity.Role;
import com.springboot.security.entity.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Set;

/**
 * <p>
 * Mapper 接口
 * </p>
 *
 * @author zhangtengfei
 * @since 2021-04-21
 */
public interface UserMapper extends BaseMapper<User> {

    /**
     * 3张表连接查询！！！！！！！！
     * 
     * @param username
     * @return
     */
    @Select({
            "SELECT " +
                    "role.* " +
                    "FROM " +
                    "`user`, user_role, role " +
                    "WHERE " +
                    "`user`.username = #{username} AND `user`.id = user_role.user_id AND user_role.role_id = role.id"
    })
    Set<Role> getUserRole(@Param("username") String username);
}
