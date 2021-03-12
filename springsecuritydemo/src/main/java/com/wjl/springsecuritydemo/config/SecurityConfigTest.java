package com.wjl.springsecuritydemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * 自定义编写实现类配置
 * @author wangJiaLun
 * @date 2021-03-12
 **/
@Configuration
public class SecurityConfigTest extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService myUserDetailsService;

    @Autowired
    private DataSource dataSource;

    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        // 启动时候创建表
//        jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService).passwordEncoder(password());
    }

    @Bean
    PasswordEncoder password(){
        return new BCryptPasswordEncoder();
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
            .and().authorizeRequests()
                .antMatchers("/","/test/hello", "/user/login").permitAll()  // 设置哪些路径可以不认证直接访问
                // 当前登录用户，只有具有admins权限才可以访问这个路径
//                .antMatchers("/test/index").hasAuthority("admins")
//                .antMatchers("/test/index").hasAnyAuthority("admins, manager")
                // ROLE_sale
                .antMatchers("/test/index").hasRole("sale")
            .anyRequest().authenticated()
            .and()
                .rememberMe().tokenRepository(persistentTokenRepository())
                // 设置有效时常
                .tokenValiditySeconds(60)
                .userDetailsService(userDetailsService())
            .and().csrf().disable();    // 关闭csrf防护
    }
}
