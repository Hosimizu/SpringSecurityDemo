package com.shixun.security_jwt.service;

import com.shixun.security_jwt.dao.UserDao;
import com.shixun.security_jwt.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Example;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserDao userDao;

    @Override
    public Users selectUserByUserName(String userName) {
        Users user = new Users();
        user.setUserName(userName);
        List<Users> list = userDao.findAll(Example.of(user));
        System.out.println(list);
        return list.isEmpty() ? null : list.get(0);
    }
}
