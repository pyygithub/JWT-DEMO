# JWT-DEMO
SpringBoot整合JWT完成权限验证功能示例

**JWT官网： [https://jwt.io/](https://jwt.io/)**
**JWT(Java版)的github地址:[https://github.com/jwtk/jjwt](https://github.com/jwtk/jjwt)**

## 什么是JWT
>**Json Web Token（JWT）**：JSON网络令牌，是为了在网络应用环境间传递声明而制定的一种基于JSON的开放标准（(RFC 7519)。JWT是一个轻便的安全跨平台传输格式，定义了一个**紧凑的自包含**的方式用于通信双方之间以 JSON 对象行使安全的传递信息。因为数字签名的存在，这些信息是可信的。

广义上讲JWT是一个标准的名称；狭义上讲JWT指的就是用来传递的那个token字符串。

## JWT的组成
JWT含有三个部分：
- **头部（header）**
- **载荷（payload）**
- **签证（signature）**

**头部（header）**
头部一般有两部分信息：`类型`、`加密的算法`（通常使用HMAC SHA256）
头部一般使用base64加密：`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9`
解密后：
```
{
    "typ":"JWT",
    "alg":"HS256"
}
```
**载荷（payload）**
该部分一般存放一些有效的信息。JWT的标准定义包含五个字段：
- **iss**：该JWT的签发者
- **sub**：该JWT所面向的用户
- **aud**：接收该JWT的一方
- **exp（expires）**：什么时候过期，这里是一个Unit的时间戳
- **iat（issued at**）：在什么时候签发的

**签证（signature）**
JWT最后一个部分。该部分是使用了HS256加密后的数据；包含三个部分：
- **heade**r(base64后的）
- **payload**（base64后的）
- **secret** 私钥

`secret`是保存在`服务器端`的，JWT的签发生成也是在服务器端的，`secret`就是用来进行JWT的`签发`和JWT的`验证`，所以，它就是你服务端的`秘钥`，在任何场景都不应该流露出去。一旦客户端得知这个secret，那就意味着客户端可以自我签发JWT了。

## JWT特点

- **紧凑**：意味着这个字符串很小，甚至可以放在URL参数，POST Parameter中以Http Header的方式传输。
 - **自包含**：传输的字符串包含很多信息，别人拿到以后就不需要多次访问数据库获取信息，而且通过其中的信息就可以知道加密类型和方式（当然解密需要公钥和密钥）。


## 如何使用JWT？
在身份鉴定的实现中，传统的方法是在服务端存储一个  `session`，给客户端返回一个 `cookie`，而使用JWT之后，当用户使用它的认证信息登录系统之后，会返回给用户一个`JWT`， 用户只需要本地保存该 `token`（通常使用localStorage，也可以使用cookie）即可。

当用户希望访问一个受保护的路由或者资源的时候，通常应该在 `Authorization` 头部使用 `Bearer` 模式添加JWT，其内容格式：
```
Authorization: Bearer <token>
```
因为用户的状态在`服务端内容中是不存储`的，所以这是一种`无状态`的认证机制。服务端的保护路由将会检查请求头 `Authorization` 中的JWT信息，如果合法，则允许用户的行为。由于JWT是 `自包含`的，因此，减少了需要查询数据库的需要。

JWT的这些特征使得我们可以完全依赖无状态的特性提供数据API服务。因为JWT并不使用Cookie的，所以你可以在任何域名提供你的API服务而不需要担心跨域资源共享问题（CORS）

下面的序列图展示了该过程：
![](https://upload-images.jianshu.io/upload_images/11464886-9fd1cd00741d5d8d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
中文流程介绍：
1. 用户使用账号和密码发出POST登录请求；
2. 服务器使用私钥创建一个JWT；
3. 服务器返回这个JWT给浏览器；
4. 浏览器将该JWT串放在请求头中向服务器发送请求；
5. 服务器验证该JWT；
6. 返回响应的资源给浏览器。



说了这么多JWT到底如何应用到我们的项目中，下面我们就使用SpringBoot 结合 JWT完成用户的登录验证。

## 应用流程
- 初次登录生成JWT流程图
![](https://upload-images.jianshu.io/upload_images/11464886-e074e8f5891b6f3f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
- 用户访问资源流程图
![](https://upload-images.jianshu.io/upload_images/11464886-83d07cc27a3f7237.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 搭建SpringBoot + JWT工程

下面通过代码来实现用户认证的功能，博主这里主要采用Spring Boot与JWT整合的方式实现。关于Spring Boot项目如何搭建与使用本章不做详细介绍。
1. 首先引入JWT依赖：
```
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt</artifactId>
			<version>0.9.0</version>
		</dependency>
```
2. 在工程 application.yml 配置文件中添加JWT的配置信息：
```
##jwt配置
audience:
  # 代表这个JWT的接收对象,存入audience
  clientId: 098f6bcd4621d373cade4e832627b4f6
  # 密钥, 经过Base64加密, 可自行替换
  base64Secret: MDk4ZjZiY2Q0NjIxZDM3M2NhZGU0ZTgzMjYyN2I0ZjY=
  # JWT的签发主体，存入issuer
  name: restapiuser
  # 过期时间，时间戳
  expiresSecond: 172800
```
3. 新建配置信息的实体类，以便获取JWT配置：
```
@Data
@ConfigurationProperties(prefix = "audience")
@Component
public class Audience {

    private String clientId;
    private String base64Secret;
    private String name;
    private int expiresSecond;

}
```
JWT验证主要是通过过滤器验证，所以我们需要添加一个拦截器来演请求头中是否包含有后台颁发的  `token`，这里请求头的格式：
```
Authorization: Bearer <token>
```
4. 创建JWT工具类：
```
package com.thtf.util;

import com.thtf.common.exception.CustomException;
import com.thtf.common.response.ResultCode;
import com.thtf.model.Audience;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/17 17:24
 * Version: v1.0
 * ========================
 */
public class JwtTokenUtil {

    private static Logger log = LoggerFactory.getLogger(JwtTokenUtil.class);

    public static final String AUTH_HEADER_KEY = "Authorization";

    public static final String TOKEN_PREFIX = "Bearer ";

    /**
     * 解析jwt
     * @param jsonWebToken
     * @param base64Security
     * @return
     */
    public static Claims parseJWT(String jsonWebToken, String base64Security) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(DatatypeConverter.parseBase64Binary(base64Security))
                    .parseClaimsJws(jsonWebToken).getBody();
            return claims;
        } catch (ExpiredJwtException  eje) {
            log.error("===== Token过期 =====", eje);
            throw new CustomException(ResultCode.PERMISSION_TOKEN_EXPIRED);
        } catch (Exception e){
            log.error("===== token解析异常 =====", e);
            throw new CustomException(ResultCode.PERMISSION_TOKEN_INVALID);
        }
    }

    /**
     * 构建jwt
     * @param userId
     * @param username
     * @param role
     * @param audience
     * @return
     */
    public static String createJWT(String userId, String username, String role, Audience audience) {
        try {
            // 使用HS256加密算法
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);

            //生成签名密钥
            byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(audience.getBase64Secret());
            Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

            //userId是重要信息，进行加密下
            String encryId = Base64Util.encode(userId);

            //添加构成JWT的参数
            JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT")
                    // 可以将基本不重要的对象信息放到claims
                    .claim("role", role)
                    .claim("userId", userId)
                    .setSubject(username)           // 代表这个JWT的主体，即它的所有人
                    .setIssuer(audience.getClientId())              // 代表这个JWT的签发主体；
                    .setIssuedAt(new Date())        // 是一个时间戳，代表这个JWT的签发时间；
                    .setAudience(audience.getName())          // 代表这个JWT的接收对象；
                    .signWith(signatureAlgorithm, signingKey);
            //添加Token过期时间
            int TTLMillis = audience.getExpiresSecond();
            if (TTLMillis >= 0) {
                long expMillis = nowMillis + TTLMillis;
                Date exp = new Date(expMillis);
                builder.setExpiration(exp)  // 是一个时间戳，代表这个JWT的过期时间；
                        .setNotBefore(now); // 是一个时间戳，代表这个JWT生效的开始时间，意味着在这个时间之前验证JWT是会失败的
            }

            //生成JWT
            return builder.compact();
        } catch (Exception e) {
            log.error("签名失败", e);
            throw new CustomException(ResultCode.PERMISSION_SIGNATURE_ERROR);
        }
    }

    /**
     * 从token中获取用户名
     * @param token
     * @param base64Security
     * @return
     */
    public static String getUsername(String token, String base64Security){
        return parseJWT(token, base64Security).getSubject();
    }

    /**
     * 从token中获取用户ID
     * @param token
     * @param base64Security
     * @return
     */
    public static String getUserId(String token, String base64Security){
        String userId = parseJWT(token, base64Security).get("userId", String.class);
        return Base64Util.decode(userId);
    }

    /**
     * 是否已过期
     * @param token
     * @param base64Security
     * @return
     */
    public static boolean isExpiration(String token, String base64Security) {
        return parseJWT(token, base64Security).getExpiration().before(new Date());
    }
}
```

5. 创建JWT验证拦截器：
```
package com.thtf.interceptor;

import com.thtf.annotation.JwtIgnore;
import com.thtf.common.exception.CustomException;
import com.thtf.common.response.ResultCode;
import com.thtf.model.Audience;
import com.thtf.util.JwtTokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * ========================
 * token验证拦截器
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/18 9:46
 * Version: v1.0
 * ========================
 */
@Slf4j
public class JwtInterceptor extends HandlerInterceptorAdapter{

    @Autowired
    private Audience audience;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 忽略带JwtIgnore注解的请求, 不做后续token认证校验
        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            JwtIgnore jwtIgnore = handlerMethod.getMethodAnnotation(JwtIgnore.class);
            if (jwtIgnore != null) {
                return true;
            }
        }

        if (HttpMethod.OPTIONS.equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return true;
        }

        // 获取请求头信息authorization信息
        final String authHeader = request.getHeader(JwtTokenUtil.AUTH_HEADER_KEY);
        log.info("## authHeader= {}", authHeader);

        if (StringUtils.isBlank(authHeader) || !authHeader.startsWith(JwtTokenUtil.TOKEN_PREFIX)) {
            log.info("### 用户未登录，请先登录 ###");
            throw new CustomException(ResultCode.USER_NOT_LOGGED_IN);
        }

        // 获取token
        final String token = authHeader.substring(7);

        if(audience == null){
            BeanFactory factory = WebApplicationContextUtils.getRequiredWebApplicationContext(request.getServletContext());
            audience = (Audience) factory.getBean("audience");
        }

        // 验证token是否有效--无效已做异常抛出，由全局异常处理后返回对应信息
        JwtTokenUtil.parseJWT(token, audience.getBase64Secret());

        return true;
    }

}
```
6. 配置拦截器：
```
package com.thtf.config;

import com.thtf.interceptor.JwtInterceptor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/18 10:37
 * Version: v1.0
 * ========================
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
    /**
     * 添加拦截器
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        //拦截路径可自行配置多个 可用 ，分隔开
        registry.addInterceptor(new JwtInterceptor()).addPathPatterns("/**");
    }

    /**
     * 跨域支持
     *
     * @param registry
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")
                .allowCredentials(true)
                .allowedMethods("GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "HEAD")
                .maxAge(3600 * 24);
    }

}
```
这里JWT可能会有跨域问题，配置跨域支持。

7. 编写测试Controller接口：

```
package com.thtf.controller;

import com.alibaba.fastjson.JSONObject;
import com.thtf.annotation.JwtIgnore;
import com.thtf.common.response.Result;
import com.thtf.model.Audience;
import com.thtf.util.JwtTokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/18 10:41
 * Version: v1.0
 * ========================
 */
@Slf4j
@RestController
public class AdminUserController {

    @Autowired
    private Audience audience;

    @PostMapping("/login")
    @JwtIgnore
    public Result adminLogin(HttpServletResponse response, String username,String password) {
        // 这里模拟测试, 默认登录成功，返回用户ID和角色信息
        String userId = UUID.randomUUID().toString();
        String role = "admin";

        // 创建token
        String token = JwtTokenUtil.createJWT(userId, username, role, audience);
        log.info("### 登录成功, token={} ###", token);

        // 将token放在响应头
        response.setHeader(JwtTokenUtil.AUTH_HEADER_KEY, JwtTokenUtil.TOKEN_PREFIX + token);
        // 将token响应给客户端
        JSONObject result = new JSONObject();
        result.put("token", token);
        return Result.SUCCESS(result);
    }

    @GetMapping("/users")
    public Result userList() {
        log.info("### 查询所有用户列表 ###");
        return Result.SUCCESS();
    }
}
```
8. 接下来我们使用PostMan工具进行测试：

没有登录时候直接访问：http://localhost:8080/users 接口：
![](https://upload-images.jianshu.io/upload_images/11464886-f6a90fc4fcc55117.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

执行登录：
![](https://upload-images.jianshu.io/upload_images/11464886-4336b91f4ee94afd.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

携带生成token再次访问：http://localhost:8080/users 接口
![](https://upload-images.jianshu.io/upload_images/11464886-49c35a20f880c4e2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

`注意`：这里选择 `Bearer Token`类型，就把不要在 `Token`中手动`Bearer`，postman会自动拼接。









