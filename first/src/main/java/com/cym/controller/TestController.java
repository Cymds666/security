package com.cym.controller;

import com.cym.dto.R;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/13 09:18
 */
@RestController
public class TestController {
    //测试方法1  匿名访问
    @GetMapping(value = "/test1")
    public R test1(){
        return R.OK("test1");
    }

    //测试方法2  认证后才能访问
    @GetMapping(value = "/test2")
    public R test2(){
        return R.OK("test2");
    }

    //测试方法3  admin角色可以访问
    @PreAuthorize(value = "hasRole('admin')")
    @GetMapping(value = "/test3")
    public R test3(){
        return R.OK("test3");
    }
    //测试方法4 cto角色或者cfo角色可以访问
    @PreAuthorize(value = "hasAnyRole('cfo','cto')")
    @GetMapping(value = "/test4")
    public R test4(){
        return R.OK("test4");
    }
    //测试方法5 cto角色和admin角色可以访问
    @PreAuthorize(value = "hasRole('cto') and hasRole('admin')")
    @GetMapping(value = "/test5")
    public R test5(){
        return R.OK("test5");
    }

    //测试方法6 del权限可以访问
    @PreAuthorize(value = "hasAuthority('del')")
    @GetMapping(value = "/test6")
    public R test6(){
        return R.OK("test6");
    }

    //测试方法7 del或者edit权限可以访问
    @PreAuthorize(value = "hasAnyAuthority('del','edit')")
    @GetMapping(value = "/test7")
    public R test7(){
        return R.OK("test7");
    }

    //测试方法8 del和edit权限可以访问
    @PreAuthorize(value = "hasAuthority('del') and hasAuthority('edit')")
    @GetMapping(value = "/test8")
    public R test8(){
        return R.OK("test8");
    }
}
