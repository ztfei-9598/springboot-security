package com.springboot.security.domain;

import com.springboot.security.entity.Role;
import com.springboot.security.entity.User;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * @author zhangtengfei
 * @date 2021/4/22 19:41
 */

@Data
@Builder
public class MyUserDetail extends User implements UserDetails {

    /***
     * 不使用 User 实现 UserDetails 类。因为这个参数不属于 user 表中的字段
     */
    private Set<Role> roles;

    /**
     * 方法返回用户的角色信息，我们在这个方法中把自己的 Role 稍微转化一下即可
     *
     * @return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : getRoles()) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
