package com.cym.security;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/12 20:34
 */

import cn.hutool.json.JSONUtil;
import com.cym.dto.R;
import com.cym.utils.RedisClient;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * 注销成功后的处理器
 */
@Component
public class LogoutStatusSuccessHandler implements LogoutSuccessHandler {
    @Resource
    private RedisClient redisClient;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String token = request.getHeader("token");
        //判断token是否存在
        if(StringUtils.hasText(token)){
            //从redis中删除
            String key="login:token:"+token;
            redisClient.del(key);
        }
        //返回给客户端注销成功的提示
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json");
        R<Object> result = R.OK("注销成功");
        String json = JSONUtil.toJsonStr(result);
        response.getWriter().print(json);
    }
}