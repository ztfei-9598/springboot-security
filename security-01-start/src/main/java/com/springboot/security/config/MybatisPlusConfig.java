package com.springboot.security.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * 注意 mybatis-plus 配置
 * 
 * TODO: 问题 @MapperScan(basePackages = {"com.springboot.security.mapper"}) 如果没加 .mapper，报错：
 * mybatisplus org.apache.ibatis.binding.BindingException: Invalid bound statement (not found)
 * 
 * @author zhangtengfei
 * @date 2021/4/22 20:20
 */

@EnableTransactionManagement
@Configuration
@MapperScan(basePackages = {"com.springboot.security.mapper"})
public class MybatisPlusConfig {
}
