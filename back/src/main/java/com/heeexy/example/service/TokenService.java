package com.heeexy.example.service;

import com.heeexy.example.config.exception.CommonJsonException;
import com.heeexy.example.dao.LoginDao;
import com.heeexy.example.dto.session.SessionUserInfo;
import com.heeexy.example.util.JwtUtils;
import com.heeexy.example.util.StringTools;
import com.heeexy.example.util.constants.ErrorEnum;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class TokenService {


    @Autowired
    LoginDao loginDao;

    @Autowired
    RedisTemplate<String, Object> redisTemplate;

    /**
     * 用户登录验证通过后(sso/帐密),生成token,记录用户已登录的状态
     */
    public String generateToken(String username) {
        MDC.put("username", username);
        String token = JwtUtils.getToken(username);
        setCache(token, username);
        return token;
    }

    public SessionUserInfo getUserInfo() {
        String token = MDC.get("token");
        return getUserInfoFromCache(token);
    }

    /**
     * 根据token查询用户信息
     * 如果token无效,会抛未登录的异常
     */
    private SessionUserInfo getUserInfoFromCache(String token) {
        if (StringTools.isNullOrEmpty(token)) {
            throw new CommonJsonException(ErrorEnum.E_20011);
        }
        Claims claimsFromToken = JwtUtils.getClaimsFromToken(token);
        if (claimsFromToken == null) throw new CommonJsonException(ErrorEnum.E_20011);
//        if (JwtUtils.isTokenExpired(claimsFromToken)) {
//            throw new JwtException("TOKEN_EXPIRED");
//        }
        log.debug("根据token从缓存中查询用户信息,{}", token);
        String nameFromToken = JwtUtils.getNameFromToken(token);
        SessionUserInfo info = (SessionUserInfo) redisTemplate.opsForHash().get(nameFromToken, "info");
        if (info == null) {
            log.info("没拿到缓存 token={}", token);
            throw new CommonJsonException(ErrorEnum.E_20011);
        }
        return info;
    }

    private void setCache(String token, String username) {
        SessionUserInfo info = getUserInfoByUsername(username);
        log.info("设置用户信息缓存:token={} , username={}, info={}", token, username, info);
        redisTemplate.opsForHash().put(username, "info", info);
        redisTemplate.opsForHash().put(username, "token", token);
        redisTemplate.expire(username, 1, TimeUnit.DAYS);
    }

    /**
     * 退出登录时,将token置为无效
     */
    public void invalidateToken() {
        String token = MDC.get("token");
        String username = MDC.get("username");
        if (!StringTools.isNullOrEmpty(token)) {
            redisTemplate.opsForHash().delete(username, "token", "info");
        }
        log.debug("退出登录,清除缓存:token={}", token);
    }

    private SessionUserInfo getUserInfoByUsername(String username) {
        SessionUserInfo userInfo = loginDao.getUserInfo(username);
        if (userInfo.getRoleIds().contains(1)) {
            //管理员,查出全部按钮和权限码
            userInfo.setMenuList(loginDao.getAllMenu());
            userInfo.setPermissionList(loginDao.getAllPermissionCode());
        }
        return userInfo;
    }
}
