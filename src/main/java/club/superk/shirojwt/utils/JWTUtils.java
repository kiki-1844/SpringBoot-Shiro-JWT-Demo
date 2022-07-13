package club.superk.shirojwt.utils;

import cn.hutool.core.date.DateUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.UnsupportedEncodingException;
import java.util.Date;

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
