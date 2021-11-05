package com.heeexy.example.util;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author: varz1
 * description: Jwt工具类
 * @date: 2021/08/31 16:05
 */

@Slf4j
public class JwtUtils {

    final static String TOKEN_SECRET = "Secret";

    /**
     *根据用户名生成token加入jwt中
     * @param username
     * @return
     */
    public static String getToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + (3600 * 1000)))
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS256, TOKEN_SECRET)
                .compact();
    }

    /**
     * 从token中获取用户名
     * @param token
     * @return
     */
    public static String getNameFromToken(String token) {
        SimpleDateFormat sdf = new SimpleDateFormat();
        Claims secret = Jwts.parser().setSigningKey(TOKEN_SECRET).parseClaimsJws(token).getBody();
        String issueAt = sdf.format(secret.getIssuedAt());//获取签发时间
        String expireAt = sdf.format(secret.getExpiration());//获取过期时间
        log.info("TOKEN签发时间为： " + issueAt + "----过期时间为：" + expireAt);
        return secret.getSubject();
    }

    /**
     * 根据token获取Claims对象 用于判空/过期
     * @param token
     * @return
     */
    public static Claims getClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(TOKEN_SECRET)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }

//    public static boolean isTokenExpired(Claims claims) {
//        return claims.getExpiration().before(new Date());
//    }
}
