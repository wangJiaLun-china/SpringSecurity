# 特点

- 和 Spring 无缝整合。
-  全面的权限控制。
- 专门为 Web 开发而设计。
- 旧版本不能脱离 Web 环境使用。
- 新版本对整个框架进行了分层抽取，分成了核心模块和 Web 模块。单独 引入核心模块就可以脱离 Web 环境。
-  重量级。

# 权限概念

- 主体 英文单词：principal

  使用系统的用户或设备或从其他系统远程登录的用户等等。简单说就是谁使用系 统谁就是主体。

-  认证 英文单词：authentication 权限管理系统确认一个主体的身份，允许主体进入系统。简单说就是“主体”证 明自己是谁。 笼统的认为就是以前所做的登录操作。

-  授权 英文单词：authorization 将操作系统的“权力”“授予”“主体”，这样主体就具备了操作系统中特定功 能的能力。 所以简单来说，授权就是给用户分配权限。

# 过滤器

SpringSecurity 采用的是责任链的设计模式，它有一条很长的过滤器链

- WebAsyncManagerIntegrationFilter：将 Security 上下文与 Spring Web 中用于 处理异步请求映射的 WebAsyncManager 进行集成。 
- SecurityContextPersistenceFilter：在每次请求处理之前将该请求相关的安全上 下文信息加载到 SecurityContextHolder 中，然后在该次请求处理完成之后，将 SecurityContextHolder 中关于这次请求的信息存储到一个“仓储”中，然后将 SecurityContextHolder 中的信息清除，例如在 Session 中维护一个用户的安全信 息就是这个过滤器处理的。 
- HeaderWriterFilter：用于将头信息加入响应中。
- CsrfFilter：用于处理跨站请求伪造。 
- LogoutFilter：用于处理退出登录。 
- **UsernamePasswordAuthenticationFilter**：用于处理基于表单的登录请求，从表单中 获取用户名和密码。默认情况下处理来自 /login 的请求。从表单中获取用户名和密码 时，默认使用的表单 name 值为 username 和 password，这两个值可以通过设置这个 过滤器的 usernameParameter 和 passwordParameter 两个参数的值进行修改。 
- DefaultLoginPageGeneratingFilter：如果没有配置登录页面，那系统初始化时就会 配置这个过滤器，并且用于在需要进行登录时生成一个登录表单页面。 
- BasicAuthenticationFilter：检测和处理 http basic 认证。
- RequestCacheAwareFilter：用来处理请求的缓存。 
- SecurityContextHolderAwareRequestFilter：主要是包装请求对象 request。 
- AnonymousAuthenticationFilter：检测 SecurityContextHolder 中是否存在 Authentication 对象，如果不存在为其提供一个匿名 Authentication。 
- SessionManagementFilter：管理 session 的过滤器 
- **ExceptionTranslationFilter**：是个异常过滤器，用来处理在认证授权过程中抛出的异常处理 AccessDeniedException 和 AuthenticationException 异常。 
- **FilterSecurityInterceptor**：是一个方法级的权限过滤器, 基本位于过滤链的最底部。可以看做过滤器链的出口。 
- RememberMeAuthenticationFilter：当用户没有登录而直接访问资源时, 从 cookie  里找出用户的信息, 如果 Spring Security 能够识别出用户提供的 remember me cookie,  用户将不必填写用户名和密码, 而是直接登录进入系统，该过滤器默认不开启。

# 核心接口

- UserDetailsService  接口: 当什么也没有配置的时候，账号和密码是由 Spring Security 定义生成的。而在实际项目中 账号和密码都是从数据库中查询出来的。 所以我们要通过自定义逻辑控制认证逻辑。 如果需要自定义逻辑时，只需要实现 UserDetailsService 接口即可。

  创建类继承UsernamePasswordAuthenticationFilter ，重写三个方法

  创建类实现UserDetailsService，编写查询数据过程，返回安全框架提供的User对象

- PasswordEncoder 接口: 数据加密接口，用于返回User对象密码加密

# web权限

### 认证

- 1.设置登录的用户名和密码

    - 通过配置文件

      ```properties
      spring.security.user.name=wjl
      spring.security.user.password=wjl
      ```

    - 通过配置类

      ```java
      @Configuration
      public class SecurityConfig extends WebSecurityConfigurerAdapter {
      
          @Override
          protected void configure(AuthenticationManagerBuilder auth) throws Exception {
              BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
              String password = passwordEncoder.encode("123");
              auth.inMemoryAuthentication().withUser("wjl").password(password).roles("");
          }
      
          @Bean
          PasswordEncoder password(){
              return new BCryptPasswordEncoder();
          }
          
              @Override
          protected void configure(HttpSecurity http) throws Exception {
              http.formLogin() // 自定义登录页面
                  .loginPage("/login.html") // 登录页面设置
                  .loginProcessingUrl("/user/login") // 登录访问路径
                  .defaultSuccessUrl("/test/index").permitAll()  // 登录成功之后，跳转路径
                  .and().authorizeRequests()
                      .antMatchers("/","/test/hello", "/user/login").permitAll()  // 设置哪些路径可以不认证直接访问
                  .anyRequest().authenticated()
                  .and().csrf().disable();    // 关闭csrf防护
          }
      }
      ```



- 自定义编写实现类

    - 创建配置类，设置使用哪个userDetailsService实现类

      ```java
      @Configuration
      public class SecurityConfigTest extends WebSecurityConfigurerAdapter {
      
          @Autowired
          private UserDetailsService myUserDetailsService;
      
          @Override
          protected void configure(AuthenticationManagerBuilder auth) throws Exception {
              auth.userDetailsService(userDetailsService).passwordEncoder(password());
          }
      
          @Bean
          PasswordEncoder password(){
              return new BCryptPasswordEncoder();
          }
      }
      ```



    - 编写userDetailsService实现类,返回User对象，User对象有用户名密码和操作权限
    
      ```java
      @Service("myUserDetailsService")
      public class MyUserDetailsService implements UserDetailsService {
      
          @Override
          public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
              List<GrantedAuthority> authorityList =
                      AuthorityUtils.commaSeparatedStringToAuthorityList("role");
              return new User("wjl", new BCryptPasswordEncoder().encode("234"), authorityList);
          }
      }
      ```

### 基于角色权限进行访问控制

- hasAuthority 方法： 如果当前的主体具有指定的权限，则返回 true,否则返回 false

    - 在配置类设置当前路径有哪些权限

      ```java
      // 当前登录用户，只有具有admins权限才可以访问这个路径
      .antMatchers("/test/index").hasAuthority("admins")  
      ```

    - userDetailsService里面设置权限

      ```java
      List<GrantedAuthority> authorityList =
                      AuthorityUtils.commaSeparatedStringToAuthorityList("admins");
      ```

- hasAnyAuthority方法: 如果当前的主体有任何提供的角色（给定的作为一个逗号分隔的字符串列表）的话，返回 true。

    - ```java
      .antMatchers("/test/index").hasAnyAuthority("admins, manager")
      ```
    ```
    
    ```

- hasRole 方法: 如果用户具备给定角色就允许访问,否则出现 403。 如果当前主体具有指定的角色，则返回 true。

    - ```java
      return "hasRole('ROLE_" + role + "')";
      ```
    ```
    
    - ```java
    List<GrantedAuthority> authorityList =
            AuthorityUtils.commaSeparatedStringToAuthorityList("admins, ROLE_sale");
    ```

- hasAnyRole方法: 表示用户具备任何一个条件都可以访问。



- 自定义403没有访问权限页面

  ```java
      protected void configure(HttpSecurity http) throws Exception {
          // 配置无权限访问自定义页面
          http.exceptionHandling().accessDeniedPage("/unauth.html");
  ```

### 认证授权注解

- @secured

  判断是否具有角色，另外需要注意的是这里匹配的字符串需要添加前缀“ROLE_“。

    - 启动类，配置类 @EnableGlobalMethodSecurity(securedEnabled=true)

    - controller 方法上配置注解，设置角色

      ```java
      @GetMapping("/update")
      @Secured({"ROLE_sale", "ROLE_manager"})
      public String update(){
          return "hello update";
      }
      ```

    - userDetailsService 设置角色

      ```java
      List<GrantedAuthority> authorityList =
          AuthorityUtils.commaSeparatedStringToAuthorityList("admins, ROLE_sale");
      ```

- @PreAuthorize

  注解适合进入方法前的权限验证， @PreAuthorize 可以将登录用 户的 roles/permissions 参数传到方法中。

    - 启动类开启注解 @EnableGlobalMethodSecurity(securedEnabled=true, prePostEnabled = true)

    - ```java
      @PreAuthorize("hasAnyAuthority('admins, manager')")
      ```
    ```
  
    ```

- @PostAuthorize

  在方法执行后再进行权限验证，适合验证带有返回值 的权限.

    - 启动类开启注解 @EnableGlobalMethodSecurity(securedEnabled=true, prePostEnabled = true)

    - ```java
      @PostAuthorize("hasAnyAuthority('admins, manager')")
      ```
    ```
  
    ```

-  @PostFilter

权限验证之后对数据进行过滤

- @PreFilter

  进入控制器之前对数据进行过滤

### 用户注销

- 配置类中添加推出配置

  ```java
  http.logout().logoutUrl("/logout").logoutSuccessUrl("/index").permitAll();
  ```

### 免登录

- cookie技术

- 安全框架机制实现自动登录

  实现原理

    - 认证成功后向浏览器存储 cookie，加密串。向数据库存储用户信息和加密串

    - 再次访问从浏览器获取cookies信息，拿cookies到数据库比对，如果查询到

      对应信息，认证成功可以登录

![image-20210312155058203](D:\资料\笔记\image\image-20210312155058203.png)

sql : JdbcTokenRepositoryImpl 类中有

```sql
create table persistent_logins (username varchar(64) not null, series varchar(64) primary key, token varchar(64) not null, last_used timestamp not null);
```

配置类

```java
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        // 启动时候创建表
//        jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 退出
        http.logout().logoutUrl("/logout").logoutSuccessUrl("/index").permitAll();

        // 配置无权限访问自定义页面
        http.exceptionHandling().accessDeniedPage("/unauth.html");
        http.formLogin() // 自定义登录页面
            .loginPage("/login.html") // 登录页面设置
            .loginProcessingUrl("/user/login") // 登录访问路径
            .defaultSuccessUrl("/success.html").permitAll()  // 登录成功之后，跳转路径
            .and()
                .rememberMe().tokenRepository(persistentTokenRepository())
                // 设置token有效时常
                .tokenValiditySeconds(60)
                .userDetailsService(userDetailsService())
            .and().csrf().disable();    // 关闭csrf防护
    }
```

### CSRF

```markdown
跨站请求伪造（英语：Cross-site request forgery），也被称为 one-click  attack 或者 session riding，通常缩写为 CSRF 或者 XSRF， 是一种挟制用户在当前已 登录的 Web 应用程序上执行非本意的操作的攻击方法。跟跨网站脚本（XSS）相比，XSS 利用的是用户对指定网站的信任，CSRF 利用的是网站对用户网页浏览器的信任。 跨站请求攻击，简单地说，是攻击者通过一些技术手段欺骗用户的浏览器去访问一个 自己曾经认证过的网站并运行一些操作（如发邮件，发消息，甚至财产操作如转账和购买 商品）。由于浏览器曾经认证过，所以被访问的网站会认为是真正的用户操作而去运行。 这利用了 web 中用户身份验证的一个漏洞：简单的身份验证只能保证请求发自某个用户的 浏览器，却不能保证请求本身是用户自愿发出的。 从 Spring Security 4.0 开始，默认情况下会启用 CSRF 保护，以防止 CSRF 攻击应用 程序，Spring Security CSRF 会针对 PATCH，POST，PUT 和 DELETE 方法进行防护。
```

# 微服务权限

### 认证授权过程分析 [项目地址](https://github.com/wangJiaLun-china/SpringSecurity)

- 如果是基于 Session，那么 Spring-security 会对 cookie 里的 sessionid 进行解析，找 到服务器存储的 session 信息，然后判断当前用户是否符合请求的要求。 

- 如果是 token，则是解析出 token，然后将当前请求加入到 Spring-security 管理的权限 信息中去，

  如果系统的模块众多，每个模块都需要进行授权与认证，所以我们选择基于 token 的形式 进行授权与认证，用户根据用户名密码认证成功，然后获取当前用户角色的一系列权限 值，并以用户名为 key，权限列表为 value 的形式存入 redis 缓存中，根据用户名相关信息 生成 token 返回，浏览器将 token 记录到 cookie 中，每次调用 api 接口都默认将 token 携带 到 header 请求头中，Spring-security 解析 header 头获取 token 信息，解析 token 获取当前 用户名，根据用户名就可以从 redis 中获取权限列表，这样 Spring-security 就能够判断当前 请求是否有权限访问

![image-20210312172129213](D:\资料\笔记\image\image-20210312172129213.png)

