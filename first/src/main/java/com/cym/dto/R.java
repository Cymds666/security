package com.cym.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/10 19:04
 */
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class R<T> {
    /*
    响应消息
     */
    private String message = "ok";
    /*
    状态码
     */
    private Integer code = 200;
    /*
    响应数据
     */
    private T data;

    // 用于构建成功地响应，不携带数据
    public static <T> R<T> OK() {
        return R.<T>builder()
                .code(200)
                .message("成功")
                .build();
    }

    public static <T> R<T> OK(String msg) {
        return R.<T>builder()
                .code(200)
                .message(msg)
                .build();
    }

    public static <T> R<T> OK(T data) {
        return R.<T>builder()
                .code(200)
                .message("成功")
                .data(data)
                .build();
    }


    public static <T> R<T> OK(T data, String msg) {
        return R.<T>builder()
                .code(200)
                .message(msg)
                .data(data)
                .build();
    }

    // 用于构建失败的响应，不带任何参数，默认状态码为400，消息为"失败"
    public static <T> R<T> FAIL() {
        return R.<T>builder()
                .code(400)
                .message("失败")
                .build();
    }

    // 用于构建失败的响应，不带任何参数，默认状态码为400，消息为"失败"
    public static <T> R<T> FAIL(String msg) {
        return R.<T>builder()
                .code(400)
                .message(msg)
                .build();
    }

    // 用于构建失败的响应，不带任何参数，默认状态码为400，消息为"失败"
    public static <T> R<T> FAIL(int code, String msg) {
        return R.<T>builder()
                .code(code)
                .message(msg)
                .build();
    }
}
