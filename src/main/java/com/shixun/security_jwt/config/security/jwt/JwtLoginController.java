package com.shixun.security_jwt.config.security.jwt;

import com.shixun.security_jwt.common.RestResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtLoginController {
    @Autowired
    JwtAuthService jwtAuthService;
    @PostMapping("/login")
    public RestResult login(String username,String password){
        RestResult restResult=RestResult.success();
        String token=jwtAuthService.login(username,password);
        restResult.put("token",token);
        return restResult;
    }
}
