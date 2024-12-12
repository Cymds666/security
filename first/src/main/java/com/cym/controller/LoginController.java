package com.cym.controller;

import cn.hutool.json.JSONUtil;
import com.cym.dto.R;
import com.cym.security.MyUserDetails;
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
    private RedisClient redisClient;
    
    @Resource
    private AuthenticationManager authenticationManager;

    @RequestMapping("/login")
    public R<Object> hello(String username, String password, HttpServletRequest request) {
        // 验证是否曾经登陆过
        // 若登陆过，将redis里之前存储的token删掉
        // 否则redis会存储统一用户的多个tokenp
        String headerToken = request.getHeader("token");
        if (StringUtils.hasText(headerToken)) {
            String claim = JwtUtils.getClaim(headerToken);
            if (StringUtils.hasText(claim) && Objects.equals(username, claim)) {
                redisClient.del("login:token:" + headerToken);
            }
        }


        UsernamePasswordAuthenticationToken x = new UsernamePasswordAuthenticationToken(username, password);
        try{
            Authentication authenticate = authenticationManager.authenticate(x);
            if (Objects.isNull(authenticate)) {
                return R.FAIL("认证失败");
            }
            String token = JwtUtils.sign(username, 1000 * 60 * 60 * 24 * 7L);

            MyUserDetails principal = (MyUserDetails) authenticate.getPrincipal();
            String jsonStr = JSONUtil.toJsonStr(principal);
            String key = "login:token:" + token;
            redisClient.set(key, jsonStr, 1000 * 60 * 60 * 24 * 7L);
            System.out.println(redisClient.get(key));
            Map<String, String> map = new HashMap<>();
            map.put("token", token);
            return R.OK(map);
        }catch (Exception e) {
            return R.FAIL("认证失败");
        }
    }

    @RequestMapping("/test")
    public R test() {
        return R.OK();
    }
}
