package com.cym;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/10 14:11
 */

@SpringBootTest
public class MyApplicationTests {

    @Test
    public void test() {
        String x = "12345678";
        System.out.println(new BCryptPasswordEncoder().encode(x));
    }
}
