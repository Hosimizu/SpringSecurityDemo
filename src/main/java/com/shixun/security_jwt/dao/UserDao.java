package com.shixun.security_jwt.dao;

import com.shixun.security_jwt.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
//Long一定要对应Entity中主键的类型 不然查询会出错
public interface UserDao extends JpaRepository<Users, Long> {

}
