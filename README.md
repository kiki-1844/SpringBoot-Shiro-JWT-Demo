
### 在 pom.xml 文件中添加相关依赖

***

```xml
<!-- shiro -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.3.2</version>
</dependency>

<!-- JWT -->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.2.0</version>
</dependency>

<!-- hutool工具类 -->
<dependency>
    <groupId>cn.hutool</groupId>
    <artifactId>hutool-all</artifactId>
    <version>5.8.4</version>
</dependency>
```



### 在数据库中设置用户权限表

***

#### 建表

![数据库](https://img-blog.csdnimg.cn/973e96a3e9b54a48ab9e4ae2308459c0.png)




#### 在项目中建实体类

##### entity.User.java

```java
@Data
public class User {

    private Integer id;
    private String username;
    private String password;
    private String role;
    private String permission;

}
```



#### 编写 SQL 查询语句

##### mapper.UserMapper.java

```java
@Mapper
public interface UserMapper {

    @Select("SELECT * FROM `user`")
    List<User> findAll();

    @Select("SELECT * FROM `user` WHERE username = #{username}")
    User findById(@Param("username") String username);

    @Select("SELECT * FROM `user` WHERE username = #{username} AND password = #{password}")
    User findOne(@Param("username") String username, @Param("password") String password);


}
```





### 配置 JWT，编写 JWTUtils.java

***

##### utils.JWTUtils.java

```java
public class JWTUtils {

    /**
     * 生成 token
     */
    public static String genToken(String username, String password) {
        try {
            String token = JWT.create()
                    .withClaim("username", username) // 将 username 保存到 token 里面作为载荷
                    .withExpiresAt(DateUtil.offsetHour(new Date(), 2)) //2小时后token过期
                    .sign(Algorithm.HMAC256(password)); // 以 password 作为 token 的密钥

            return token;
        } catch (UnsupportedEncodingException e) {
            return null;
        }

    }

    /**
     * 获取目标 token 中包含的 username
     */
    public static String getUsername(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    /**
     * 校验 token 是否正确
     */
    public static boolean verify(String token, String username, String password) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(password);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("username", username)
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            return true;
        } catch (UnsupportedEncodingException e) {
            return false;
        }
    }
}
```



### 实现登录接口

***

#### 封装请求返回结果以及自定义异常

##### interceptor.Result.java

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Result {

    // 状态码
    private int code;
    // 返回信息
    private String msg;
    // 返回数据
    private Object data;

    public Result(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}
```



##### exception.UnauthorizedException.java

```java
@Getter
public class UnauthorizedException extends RuntimeException {

    public UnauthorizedException(String msg) {
        super(msg);
    }

    public UnauthorizedException() {
        super();
    }

}
```



#### 登录接口及业务逻辑编写

##### controller.dto.UserDTO

> 接受前端登录请求的参数

```java
@Data
public class UserDTO {

    private String username;
    private String password;
    private String token;

}
```



##### controller.UserController.java

| 注解                                                         | 作用                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| **@RequiresAuthentication**                                  | 验证用户是否登录，也就是判断是否满足 subject.isAuthenticated() ==true |
| **@RequiresRoles("admin")**                                  | 当 subject 中包含 admin 角色时才可以访问该方法               |
| **@RequiresPermissions(logical = Logical.AND, value = {"view", "edit"})** | 当 subject 中同时包含 view 和 edit 权限时才可以访问该方法    |

```java
@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public Result login(@RequestBody UserDTO userDTO) throws UnsupportedEncodingException {
        UserDTO dto = userService.login(userDTO);
        return new Result(200, "登录成功！", dto);
    }

    @GetMapping("/content")
    public Result content() {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            return new Result(200, "你目前处于已登录状态！");
        } else {
            return new Result(200, "你目前处于未登录状态！");
        }
    }

    @GetMapping("/require_auth")
    @RequiresAuthentication
    public Result requireAuth() {
        return new Result(200, "你已通过身份验证！");
    }

    @GetMapping("/require_role")
    @RequiresRoles("admin")
    public Result requireRole() {
        return new Result(200, "你当前处于管理员页面");
    }

    @GetMapping("/require_permission")
    @RequiresPermissions(logical = Logical.AND, value = {"view", "edit"})
    public Result requirePermission() {
        return new Result(200, "你当前可以进行查看与修改操作");
    }

    @RequestMapping(path = "/401")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Result unauthorized() {
        return new Result(401, "你当前未通过身份验证！");
    }

}
```



##### service.UserService.java

```java
@Service
public class UserService {

    @Autowired
    UserMapper userMapper;

    public User getUserById(String username) {
        return userMapper.findById(username);
    }

    public UserDTO login(UserDTO userDTO) throws UnsupportedEncodingException {

        User one = userMapper.findOne(userDTO.getUsername(), userDTO.getPassword());

        if (one != null) {
            String token = JWTUtils.genToken(one.getUsername(), one.getPassword());
//            System.out.println("登录成功，token为：----------" + token);
            userDTO.setToken(token);
            // 把 one 的属性复制给 userDTO
            BeanUtil.copyProperties(one, userDTO, true);
            return userDTO;
        } else {
            throw new UnauthorizedException();
        }
    }
}
```



### 配置 Shiro

***

#### 实现 JWTToken

##### shiro.JWTToken.java

> JWTToken 可以看作 Shiro 用户名密码的载体

```java
public class JWTToken implements AuthenticationToken {

    // 密钥
    private String token;

    public JWTToken(String token) {
        this.token = token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
```



#### 实现 Realm

> 对用户进行身份验证与授权

##### shiro.MyRealm.java

```java
@Service
public class MyRealm extends AuthorizingRealm {

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JWTToken;
    }

    /**
     * 只有当需要检测用户权限时才会调用此方法，如 checkRole，checkPermission 之类
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = JWTUtils.getUsername(principals.toString());
        User user = userService.getUserById(username);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addRole(user.getRole());
        Set<String> permission = new HashSet<>(Arrays.asList(user.getPermission().split(",")));
        simpleAuthorizationInfo.addStringPermissions(permission);
        return simpleAuthorizationInfo;
    }

    /**
     * 默认使用此方法进行用户名正确与否的验证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String token = (String) authenticationToken.getCredentials();
        // 解密得到 username, 与数据库进行对比
        String username = JWTUtils.getUsername(token);
        if (username == null) {
            throw new AuthenticationException("token 无效！");
        }

        User user = userService.getUserById(username);
        if (user == null) {
            throw new AuthenticationException("用户不存在！");
        }

        if (!JWTUtils.verify(token, username, user.getPassword())) {
            throw new AuthenticationException("用户名或密码错误！");
        }
        return new SimpleAuthenticationInfo(token, token, "my_realm");
    }
}

```



#### 重写 Filter

> 所有的请求都会经过 Filter ，所以我们需要在 Filter 中进行拦截验证，并重写鉴权方法；
>
> 方法执行流程：preHandle() -> isAccessAllowed() -> isLoginAttempt() -> executeLogin()

##### shiro.JWTFilter.java

```java
public class JWTFilter extends BasicHttpAuthenticationFilter {

    /**
     * 判断用户是否想要登录
     * 检测 header 中是否包含 Authorization 字段即可
     */
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        HttpServletRequest req = (HttpServletRequest) request;
        String authorization = req.getHeader("Authorization");
        return authorization != null;
    }

    /**
     * 登录验证
     */
    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String authorization = httpServletRequest.getHeader("Authorization");

        JWTToken token = new JWTToken(authorization);
        // 交给 realm 进行登录，若错误会抛出异常并被捕获
        getSubject(request, response).login(token);
        // 若没有抛出异常则代表登录成功
        return true;
    }

    /**
     * 游客界面是所有人可见的
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginAttempt(request, response)) {
            try {
                executeLogin(request, response);
            } catch (Exception e) {
                response401(request, response);
            }
        }
        return true;
    }

    /**
     * 对跨域提供支持
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            httpServletResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(request, response);
    }

    /**
     * 将非法请求跳转到 /401
     */
    private void response401(ServletRequest request, ServletResponse response) {
        try {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            httpServletResponse.sendRedirect("/401");
        } catch (IOException e) {

        }
    }

}
```



#### 配置 Shiro

> 详见代码

##### shiro.ShiroConfig.java

```java
@Configuration
public class ShiroConfig {

    @Bean("securityManager")
    public DefaultWebSecurityManager getManager(MyRealm realm) {
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        // 使用自己的realm
        manager.setRealm(realm);

        /*
         * 关闭shiro自带的session，详情见文档
         * http://shiro.apache.org/session-management.html#SessionManagement-StatelessApplications%28Sessionless%29
         */
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        DefaultSessionStorageEvaluator defaultSessionStorageEvaluator = new DefaultSessionStorageEvaluator();
        defaultSessionStorageEvaluator.setSessionStorageEnabled(false);
        subjectDAO.setSessionStorageEvaluator(defaultSessionStorageEvaluator);
        manager.setSubjectDAO(subjectDAO);

        return manager;
    }

    @Bean("shiroFilter")
    public ShiroFilterFactoryBean factory(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();

        // 添加自己的过滤器并且取名为jwt
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("jwt", new JWTFilter());
        factoryBean.setFilters(filterMap);

        factoryBean.setSecurityManager(securityManager);
        factoryBean.setUnauthorizedUrl("/401");

        /*
         * 自定义url规则
         * http://shiro.apache.org/web.html#urls-
         */
        Map<String, String> filterRuleMap = new HashMap<>();
        // 所有请求通过我们自己的JWT Filter
        filterRuleMap.put("/**", "jwt");
        // 访问401和404页面不通过我们的Filter
        filterRuleMap.put("/401", "anon");
        factoryBean.setFilterChainDefinitionMap(filterRuleMap);
        return factoryBean;
    }

    /**
     * 下面的代码是添加注解支持
     */
    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        // 强制使用cglib，防止重复代理和可能引起代理出错的问题
        // https://zhuanlan.zhihu.com/p/29161098
        defaultAdvisorAutoProxyCreator.setProxyTargetClass(true);
        return defaultAdvisorAutoProxyCreator;
    }

    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);
        return advisor;
    }
}
```

### 功能测试

***

#### 用户登录

##### 登录成功

![\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-sQi32IzK-1657696895936)(C:\Users\SuperK\AppData\Roaming\Typora\typora-user-images\image-20220713151500428.png)\]](https://img-blog.csdnimg.cn/9cadbaf4ec50437f8da8885f4c4b361d.png)


##### 登录失败

![\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-lDm9S2ic-1657696895937)(C:\Users\SuperK\AppData\Roaming\Typora\typora-user-images\image-20220713151434271.png)\]](https://img-blog.csdnimg.cn/cd73d0bd488542d9abdb572eedf0d5fd.png)


#### 状态判断

##### 游客模式

![\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-7k2nHdqe-1657696895938)(C:\Users\SuperK\AppData\Roaming\Typora\typora-user-images\image-20220713151820982.png)\]](https://img-blog.csdnimg.cn/b275f96e812c4b4db758d1692b648272.png)


##### 登录模式

![\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-RcPV6aTm-1657696895938)(C:\Users\SuperK\AppData\Roaming\Typora\typora-user-images\image-20220713151836811.png)\]](https://img-blog.csdnimg.cn/d07f601a13ca419a81fc442ad0f92ffd.png)


#### 权限控制

##### 当前用户无权限

![\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-cXDsDulE-1657696895938)(C:\Users\SuperK\AppData\Roaming\Typora\typora-user-images\image-20220713151924672.png)\]](https://img-blog.csdnimg.cn/be6fd6f7f9bf47c683eca26f7e222f22.png)


##### 当前用户有权限

![\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-phaZzXe7-1657696895939)(C:\Users\SuperK\AppData\Roaming\Typora\typora-user-images\image-20220713152043003.png)\]](https://img-blog.csdnimg.cn/7ca3e0bb636c428d9c30be9fc202dd31.png)
