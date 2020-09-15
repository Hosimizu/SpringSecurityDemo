package com.shixun.security_jwt.service;

import com.shixun.security_jwt.model.Users;

public interface UserService {
    Users selectUserByUserName(String userName);
}
