package com.cym.security;

import cn.hutool.json.JSONUtil;
import com.cym.dto.R;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 匿名请求访问私有化资源时的处理器
 * 就是未登录时，需要返回一个R
 * 把他配置在filterchain里的exceptionHanding
 */
@Component
public class LoginUnAuthenticationEntryPointHandler implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json");
        R error = R.FAIL("用户未登录或登录已过期,请重新登录");
        String json = JSONUtil.toJsonStr(error);
        response.getWriter().print(json);
    }
}
