package com.shixun.security_jwt.config.security;

import com.shixun.security_jwt.config.security.hander.MyAuthenticationFailureHandler;
import com.shixun.security_jwt.config.security.hander.MyAuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.annotation.Resource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;
    @Resource
    UserDetailsService userDetailsService;
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .formLogin()//开启formLogin模式
                .loginPage("/login.html") //用户未登录时，访问任何资源都转跳到该路 径，即登录页面
                .loginProcessingUrl("/login") //登录表单form中action的地址，也就是处理认证请求的路径
                .usernameParameter("username") //默认是username
                .passwordParameter("password") //默认是password
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailureHandler)
//                .defaultSuccessUrl("/index") //登录成功跳转接口
//                .failureUrl("/login.html") //登录失败跳转页面
                .and() //使用and()连接
                .authorizeRequests() //配置权限
                .antMatchers("/login.html", "/login")
                .permitAll() //用户可以任意访问
                .antMatchers("/order") //需要对外暴露的资源路径
                .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN") //user角色和admin 角色都可以访问
                .antMatchers("/system/user", "/system/role", "/system/menu")
                .hasAnyRole("ADMIN") //admin角色可以访问 自动去掉ROLE_
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated() //authenticated()要求在执行该请求时，必须已经登录了应用
                .and()
                .csrf().disable();//禁用跨站csrf攻击防御，否则无法登陆成功
        httpSecurity.logout().logoutUrl("/logout");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("user")
//                .password(bCryptPasswordEncoder().encode("123456"))
//                .roles("user")
//                .and()
//                .withUser("admin")
//                .password(bCryptPasswordEncoder().encode("123456"))
//                .roles("admin")
//                .and()
//                .passwordEncoder(bCryptPasswordEncoder());//配置BCrypt加密
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }

    /**
     * 强散列哈希加密实现,官方推荐使用BCryptPasswordEncoder进行密码加密。
     * bcrypt是一种跨平台的文件加密工具。bcrypt 使用的是布鲁斯·施内尔在1993年发布的
     * Blowfish 加密算法。由它加密的文件可在所 * 有支持的操作系统和处理器上进行转移。它的口令必须
     * 是8至56个字符，并将在内部被转化为448位的密钥。
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
