package com.cym.controller;

import cn.hutool.json.JSONUtil;
import com.cym.dto.R;
import com.cym.security.MyUserDetails;
import com.cym.service.LoginService;
import com.cym.utils.JwtUtils;
import com.cym.utils.RedisClient;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/11/23 21:10
 */

@RestController
public class LoginController {
    @Resource
    private LoginService loginService;

    @RequestMapping("/login")
    public R<Object> hello(String username, String password, HttpServletRequest request) {
        return loginService.login(username, password, request);
    }

    @RequestMapping("/test")
    public R test() {
        return R.OK();
    }
}
