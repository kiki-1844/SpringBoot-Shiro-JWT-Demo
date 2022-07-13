package club.superk.shirojwt.service;

import club.superk.shirojwt.controller.dto.UserDTO;
import club.superk.shirojwt.entity.User;
import club.superk.shirojwt.exception.UnauthorizedException;
import club.superk.shirojwt.mapper.UserMapper;
import club.superk.shirojwt.utils.JWTUtils;
import cn.hutool.core.bean.BeanUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;

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
