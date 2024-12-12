package com.cym.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/12 11:26
 */

public class JwtUtils {
    private static Algorithm hmac256 = Algorithm.HMAC256("YLWTSMTJFYHDCMGSCWHSSYBZSDKC");
    /**
     * 生成token
     * @param pub  负载
     * @param expiresTime 过期时间（单位 毫秒）
     * @return token
     */
    public static String sign(String pub, Long expiresTime){
        return JWT.create() //生成令牌函数
                .withIssuer(pub) //自定义负载部分,其实就是添加Claim(jwt结构中的payload部分),可以通过源码查看
                .withExpiresAt(new Date(System.currentTimeMillis()+expiresTime)) //添加过期时间
                .sign(hmac256);
    }
    /**
     * 校验token
     */
    public static boolean verify(String token){
        JWTVerifier verifier = JWT.require(hmac256).build();
        //如果正确,直接代码向下执行,如果错误,抛异常
        verifier.verify(token);
        return true;
    }
    /**
     * 从token中获取负载
     * @param token 令牌
     * @return 保存的负载
     */
    public static String getClaim(String token){
        DecodedJWT jwt = JWT.decode(token);
        Claim iss = jwt.getClaim("iss");
        return iss.asString();
    }
}
