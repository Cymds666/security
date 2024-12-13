# 认证

## 基于数据库

### 配置自定义的MyUserDetails

```java
@Data
public class MyUserDetails implements UserDetails {
    private User user;

    public MyUserDetails(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}

```

### 配置UserDetailService

```java
@Service
@Transactional
public class MyUserDetailService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.getUserByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }

        MyUserDetails userDetails = new MyUserDetails(username, user.getPassword());
        return userDetails;
    }
}
```

### 配置类和PasswordEncoder

此时需要建立config类了

@EnableWebSecurity开启Spring Security的功能，代替了 implements WebSecurityConfigurerAdapter

```java
@Configuration //配置类
@EnableWebSecurity // 开启Spring Security的功能 代替了 implements WebSecurityConfigurerAdapter
public class SpringSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### 配置自定义的登录接口，不用默认的

其实通过以上就可以实现数据库了，不过呢，既然是前后端分离项目，我们就必须配置一个/login接口即可，不需要他默认的界面。

#### 配置SecurityFilterChain

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.
                csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }
```

#### 配置AuthenticationManager

此类的目的在Controller中，必须用他来检验账号密码是否正确，因为我们取消了默认的检验。

必须配置此类，此类主要是工具类，功能是检验账号密码是否一样，默认会自动实现，不过当你配了filterchain后，我怀疑就没有了，必须自己提供一个了。

AuthenticationManager的一个方法authenticate，他会校验账号密码，在他的一个实现类中，会调用UserDetailService的loadUserByUsername方法来检验账号密码。

```java
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
```

#### 修改Controller

要从request中封装Authentication对象，UsernamePasswordAuthenticationToken是其一个简单的实现类。

```java
    @Resource
    private AuthenticationManager authenticationManager;

    @RequestMapping("/login")
    public R<Object> hello(String username, String password) {
        // 把post表单里的账号密码封装起来
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        // 用AuthenticationManager检查账号密码
        try{
            Authentication authenticate = authenticationManager.authenticate(token);
            if (Objects.isNull(authenticate)) {
                return R.FAIL("认证失败");
            }
        }catch (Exception e){
            return R.FAIL("认证失败");
        }
        return R.OK();
    }
```

#### 配置匿名访问

此时，当我们访问别的接口时，仍然会报错，因为我们没有配置匿名访问，即当服务器报错时(请求端无token)，我们怎么样进行处理

我们首先写一个类handler。

我们还希望在认证失败或者是授权失败的情况下也能和我们的接口一样返回相同结构的json，这样可以让前端能对响应进行统一的处理。要实现这个功能我们需要知道SpringSecurity的异常处理机制。

在SpringSecurity中，如果我们在认证或者授权的过程中出现了异常会被ExceptionTranslationFilter捕获到。在ExceptionTranslationFilter中会去判断是认证失败还是授权失败出现的异常。

如果是认证过程中出现的异常会被封装成AuthenticationException然后调用**AuthenticationEntryPoint**对象的方法去进行异常处理。

如果是授权过程中出现的异常会被封装成AccessDeniedException然后调用**AccessDeniedHandler**对象的方法去进行异常处理。

所以如果我们需要自定义异常处理，我们只需要自定义AuthenticationEntryPoint和AccessDeniedHandler然后配置SpringSecurity即可。

```java
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
```

此时，虽然进入IOC容器管理，但并没有生效，我们必须将他配置在filterchain里。

修改chain

```java
    @Resource
    private LoginUnAuthenticationEntryPointHandler loginUnAuthenticationEntryPointHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.
                csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(
                        a -> a.authenticationEntryPoint(loginUnAuthenticationEntryPointHandler)
                );
        return http.build();
    }
```

#### 配置JWT

工具类：

```Java
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

```

redis是为了保存token，并且要实现每次登录，删除同一用户上次存在redis里的token。

```java
package com.cym.utils;

import jakarta.annotation.Resource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * redis数据库客户端
 */
@Component
public class RedisClient {

    @Resource
    private StringRedisTemplate stringRedisTemplate;
    /**
     * 保存数据
     */
    public void set (String key,String value){
        stringRedisTemplate.opsForValue().set(key,value);
    }
    /**
     * 保存数据-过期时间
     * @param key    键
     * @param value  值
     * @param time   过期时间,单位是 毫秒
     */
    public void set (String key,String value,Long time){
        stringRedisTemplate.opsForValue().set(key,value,time, TimeUnit.MILLISECONDS);
    }
    /**
     * 通过键获取对应的值
     * @param key 键
     * @return    值
     */
    public String get(String key){
        return stringRedisTemplate.opsForValue().get(key);
    }
    /**
     * 通过键删除对应的值
     * @param key 键
     */
    public void del(String key){
        stringRedisTemplate.delete(key);
    }
    /**
     * 判断key是否存在
     */
    public Boolean exists(String key){
        return stringRedisTemplate.hasKey(key);
    }
}
```

重写controller

```java
package com.cym.controller;

import cn.hutool.json.JSONUtil;
import com.cym.dto.R;
import com.cym.utils.JwtUtils;
import com.cym.utils.RedisClient;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
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
        // 否则redis会存储统一用户的多个token
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

            UserDetails principal = (UserDetails) authenticate.getPrincipal();
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

```

定义JwtFilter，这是为了在过滤器链的最开始加入一个filter，用来处理用户已经登录时，访问其他非login接口的情况。

处理思路：拿到header里的token，解析，若redis存在，即已经登录，那么将用户信息存在**securitycontext**中，使之后的过滤器可以拿到并处理。

注意：必须放在SecurityContext中，之后的某过滤器会提取安全上下文中的认证信息进行认证。

```java
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

```

把过滤器链注册到config中。

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.
                csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(
                        a -> a.authenticationEntryPoint(loginUnAuthenticationEntryPointHandler)
                ).addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
```

### 注销

注销可以使用他原本定义的接口，不过要重写他的类，即LogoutSuccessHandler。

```java
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
```

在config注册

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.
                csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(
                        a -> a.authenticationEntryPoint(loginUnAuthenticationEntryPointHandler))
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(a -> a.logoutSuccessHandler(logoutSuccessHandler));
        return http.build();
    }
```

# 授权

在SpringSecurity中，会使用默认的FilterSecurityInterceptor来进行权限校验。在FilterSecurityInterceptor中会从SecurityContextHolder获取其中的Authentication，然后获取其中的权限信息。当前用户是否拥有访问当前资源所需的权限。

所以我们在项目中只需要把当前登录用户的权限信息也存入Authentication。然后设置我们的资源所需要的权限即可。

### 开启数据库日志

在yaml文件中

```yaml
mybatis:
  mapper-locations: classpath:mapper/*.xml
  type-aliases-package: com.cym.pojo
  configuration:
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
    map-underscore-to-camel-case: true
```

### 设计数据库表

![image-20241213090308439](C:\Users\79878\AppData\Roaming\Typora\typora-user-images\image-20241213090308439.png)

```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for permission
-- ----------------------------
DROP TABLE IF EXISTS `permission`;
CREATE TABLE `permission`  (
  `permission_id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '权限ID主键',
  `permission_name` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '权限名',
  PRIMARY KEY (`permission_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1002 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = '权限表' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of permission
-- ----------------------------
INSERT INTO `permission` VALUES (1000, 'del');
INSERT INTO `permission` VALUES (1001, 'edit');

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role`  (
  `role_id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '角色ID主键',
  `role_name` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '角色名',
  PRIMARY KEY (`role_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1003 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = '角色表' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES (1000, 'admin');
INSERT INTO `role` VALUES (1001, 'cto');
INSERT INTO `role` VALUES (1002, 'cfo');

-- ----------------------------
-- Table structure for role_permission
-- ----------------------------
DROP TABLE IF EXISTS `role_permission`;
CREATE TABLE `role_permission`  (
  `role_id` bigint(20) NOT NULL COMMENT '角色ID',
  `permission_id` bigint(20) NOT NULL COMMENT '权限ID',
  PRIMARY KEY (`role_id`, `permission_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = '角色权限关联表' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of role_permission
-- ----------------------------
INSERT INTO `role_permission` VALUES (1001, 1000);
INSERT INTO `role_permission` VALUES (1001, 1001);

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `user_id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '用户ID主键',
  `phone` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '手机号，唯一',
  `password` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '密码',
  `username` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '用户名',
  PRIMARY KEY (`user_id`) USING BTREE,
  UNIQUE INDEX `phone`(`phone`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1002 CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = '用户表' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES (1000, '18888888888', '$2a$10$5ftqFoPO6In7F/k4RQ./rez1IOSdl8/GBm0UMdyswZaELOV7AzDIa', 'cym');
INSERT INTO `user` VALUES (1001, '18888888889', '$2a$10$5ftqFoPO6In7F/k4RQ./rez1IOSdl8/GBm0UMdyswZaELOV7AzDIa', 'lll');

-- ----------------------------
-- Table structure for user_role
-- ----------------------------
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role`  (
  `user_id` bigint(20) NOT NULL COMMENT '用户ID',
  `role_id` bigint(20) NOT NULL COMMENT '角色ID',
  PRIMARY KEY (`user_id`, `role_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci COMMENT = '用户角色关联表' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of user_role
-- ----------------------------
INSERT INTO `user_role` VALUES (1000, 1000);
INSERT INTO `user_role` VALUES (1000, 1001);

SET FOREIGN_KEY_CHECKS = 1;
```

### 修改MyUserDetails

```java
@Data
@AllArgsConstructor
public class MyUserDetails implements UserDetails {
    private List<String> permissions;
    private List<String> roleNames;
    private User user;

    public MyUserDetails(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (!CollectionUtils.isEmpty(permissions)) {
            for (String permission : permissions) {
                authorities.add(new SimpleGrantedAuthority(permission));
            }
        }
        if (!CollectionUtils.isEmpty(roleNames)) {
            for (String roleName : roleNames) {
                authorities.add(new SimpleGrantedAuthority(roleName));
            }
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}

```



### 修改UserDetailsService

```java
@Service
@Transactional
public class MyUserDetailService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.getUserByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        System.out.println("userId = " + user.getUserId());
        List<UserRole> userRoles = userMapper.getRoleIdByUserId(user.getUserId());
        List<String> permission = new ArrayList<>();
        List<String> roleNames = new ArrayList<>();
        if (userRoles != null) {
            List<Long> roleIdList = userRoles.stream().map(UserRole::getRoleId).collect(Collectors.toList());

            List<Role> roles = userMapper.getRolesByRoleIds(roleIdList);
            if (roles != null) {
                for (Role role : roles) {
                    roleNames.add("ROLE_" + role.getRoleName());
                }
            }

            List<RolePermission> permissionsByRoleIds = userMapper.getPermissionsByRoleIds(roleIdList);
            if (permissionsByRoleIds != null) {
                List<Long> permissionIdList = permissionsByRoleIds.stream().map(RolePermission::getPermissionId).toList();
                List<Permission> permissions = userMapper.getPermissionsByIds(permissionIdList);
                if (permissions != null) {
                    for (Permission p : permissions) {
                        permission.add(p.getPermissionName());
                    }
                }
            }
        }

        return new MyUserDetails(permission, roleNames, user);
    }
}
```

### 添加授权处理器

用于处理没有权限的报错

```java
@Component
public class LoginUnAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json");
        R result = R.FAIL("权限不足,请重新授权。");
        //将消息json化
        String json = JSONUtil.toJsonStr(result);
        //送到客户端
        response.getWriter().print(json);
    }
}
```

添加到config

```java
    @Resource
    private LoginUnAccessDeniedHandler loginUnAccessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.
                csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/login", "/test1").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(
                        a -> a.authenticationEntryPoint(loginUnAuthenticationEntryPointHandler)
                                .accessDeniedHandler(loginUnAccessDeniedHandler))
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(a -> a.logoutSuccessHandler(logoutSuccessHandler))
                .cors(AbstractHttpConfigurer::disable);
        return http.build();
    }
```

### 方法

在config上开启MethodSecurity

```java
@EnableGlobalMethodSecurity
```

```java
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
```



### 其他方法

hasAnyAuthority方法可以传入多个权限，只有用户有其中任意一个权限都可以访问对应资源。

```java
@PreAuthorize("hasAnyAuthority('admin','test','system:dept:list')")
public String hello(){
      return "hello";
}
```

hasRole要求有对应的角色才可以访问，但是它内部会把我们传入的参数拼接上 **ROLE_** 后再去比较。所以这种情况下要用用户对应的权限也要有 **ROLE_** 这个前缀才可以。

```java
@PreAuthorize("hasRole('system:dept:list')")
public String hello(){
    return "hello";
}
```

hasAnyRole 有任意的角色就可以访问。它内部也会把我们传入的参数拼接上 **ROLE_** 后再去比较。所以这种情况下要用用户对应的权限也要有 **ROLE_** 这个前缀才可以。

```java
@PreAuthorize("hasAnyRole('admin','system:dept:list')")
public String hello(){
    return "hello";
}
```
