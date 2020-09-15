package com.shixun.security_jwt.config.security.service;

import com.shixun.security_jwt.model.Users;
import com.shixun.security_jwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserService userService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users users = userService.selectUserByUserName(username);
        if(users == null){
            throw new UsernameNotFoundException("登录用户： " + username + " 不存在");
        }
        //把逗号去掉
        users.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(users.getRoles()));
        System.out.println("SpringSecurity返回的users："+users);
        return users;
    }
}
