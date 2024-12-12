package com.cym;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/11/23 21:06
 */

@SpringBootApplication
@MapperScan("com.cym.dao")
public class MyApplication {
    public static void main(String[] args) {
        ConfigurableApplicationContext context = SpringApplication.run(MyApplication.class, args);
        System.out.println("123");
    }


}
