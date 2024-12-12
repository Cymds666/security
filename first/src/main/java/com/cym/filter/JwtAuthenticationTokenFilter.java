package com.cym.filter;

import cn.hutool.json.JSONUtil;
import com.cym.security.MyUserDetails;
import com.cym.utils.RedisClient;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

/**
 * 统一token凭据处理
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Resource
    private RedisClient redisClient;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if(StringUtils.hasText(token)){
            String key="login:token:"+token;
            String json = redisClient.get(key);
            if(StringUtils.hasText(json)){
                MyUserDetails userDetails = JSONUtil.toBean(json, MyUserDetails.class);
                if(Objects.nonNull(userDetails)){
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }else {
                    SecurityContextHolder.getContext().setAuthentication(null);
                }
            }
        }
        //放行,后面交给Spring Security 框架
        filterChain.doFilter(request,response);
    }
}
