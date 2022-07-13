package club.superk.shirojwt.controller;

import club.superk.shirojwt.controller.dto.UserDTO;
import club.superk.shirojwt.interceptor.Result;
import club.superk.shirojwt.mapper.UserMapper;
import club.superk.shirojwt.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;

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
