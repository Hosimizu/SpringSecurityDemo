package com.shixun.security_jwt.config.security;

import com.shixun.security_jwt.config.security.hander.MyAuthenticationFailureHandler;
import com.shixun.security_jwt.config.security.hander.MyAuthenticationSuccessHandler;
import com.shixun.security_jwt.config.security.jwt.JwtAuthTokenFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;
    @Resource
    UserDetailsService myUserDetailsService;
    @Resource
    JwtAuthTokenFilter jwtAuthTokenFilter;

    /**
     * 解决 无法直接注入 AuthenticationManager
     *
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // 认证失败处理类
                //.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                // 基于token，所以不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //配置权限
                .authorizeRequests()
                // 对于登录login 验证码captchaImage 允许匿名访问
                .antMatchers("/login").anonymous()
                .antMatchers(
                        HttpMethod.GET,
                        "/*.html",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                ).permitAll()
                .antMatchers("/order") //需要对外暴露的资源路径
                .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")  //user角色和admin角色都可以访问
                .antMatchers("/system/user", "/system/role", "/system/menu")
                .hasAnyRole("ADMIN")  //admin角色可以访问
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated().and()//authenticated()要求在执行该请求时，必须已经登录了应用
                // CRSF禁用，因为不使用session
                .csrf().disable();//禁用跨站csrf攻击防御，否则无法登陆成功
        //登出功能
        httpSecurity.logout().logoutUrl("/logout");
        // 添加JWT filter
        httpSecurity.addFilterBefore(jwtAuthTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }

//    @Override 自定义数据表验证
//    protected void configure(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity
//                .formLogin()//开启formLogin模式
//                    .loginPage("/login.html") //用户未登录时，访问任何资源都转跳到该路径，即登录页面
//                    .loginProcessingUrl("/login") //登录表单form中action的地址，也就是处理认证请求的路径
//                    .usernameParameter("username") //默认是username
//                    .passwordParameter("password") //默认是password
////                    .defaultSuccessUrl("/index") //登录成功跳转接口
////                    .failureUrl("/login.html") //登录失败跳转页面
//                    .successHandler(successHandler)
//                    .failureHandler(failureHandler)
//                    .and() //使用and()连接
//                .authorizeRequests() //配置权限
//                    .antMatchers("/login.html", "/login")
//                    .permitAll() //用户可以任意访问
//                    .antMatchers("/order") //需要对外暴露的资源路径
//                    .hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")  //user角色和admin角色都可以访问
//                    .antMatchers("/system/user", "/system/role", "/system/menu")
//                    .hasAnyRole("ADMIN")  //admin角色可以访问
//                    // 除上面外的所有请求全部需要鉴权认证
//                    .anyRequest().authenticated() //authenticated()要求在执行该请求时，必须已经登录了应用
//                    .and()
//                .csrf().disable() ;//禁用跨站csrf攻击防御，否则无法登陆成功
//        //登出功能
//        httpSecurity.logout().logoutUrl("/logout");
//    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }

//    @Override 基于内存数据
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("user")
//                .password(bCryptPasswordEncoder().encode("123456"))
//                .roles("USER")
//                .and()
//                .withUser("admin")
//                .password(bCryptPasswordEncoder().encode("123456"))
//                .roles("ADMIN")
//                .and()
//                .passwordEncoder(bCryptPasswordEncoder());//配置BCrypt加密
//    }

    /**
     * 强散列哈希加密实现
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
