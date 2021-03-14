package com.wjl.security.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class TokenManager {
    //token有效时长
    private long tokenEcpiration = 24*60*60*1000;
    //编码秘钥
    private String tokenSignKey = "123456";
    //1 使用jwt根据用户名生成token
    public String createToken(String username) {
        String token = Jwts.builder().setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis()+tokenEcpiration))
                .signWith(SignatureAlgorithm.HS512, tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
        return token;
    }
    //2 根据token字符串得到用户信息
    public String getUserInfoFromToken(String token) {
        String userinfo = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
        return userinfo;
    }
    //3 删除token
    public void removeToken(String token) { }


    public static void main(String[] args) {
        String token = Jwts.builder().setSubject("wangjialun")
                .setExpiration(new Date(System.currentTimeMillis()+24*60*60*1000))
                .signWith(SignatureAlgorithm.HS512, "123456").compressWith(CompressionCodecs.GZIP).compact();
        String userinfo = Jwts.parser().setSigningKey("123456").parseClaimsJws(token).getBody().getSubject();
        System.out.println(userinfo);

    }
}
