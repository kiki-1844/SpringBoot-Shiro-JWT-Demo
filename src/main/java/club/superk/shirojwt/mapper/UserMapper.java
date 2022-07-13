package club.superk.shirojwt.mapper;

import club.superk.shirojwt.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface UserMapper {

    @Select("SELECT * FROM `user`")
    List<User> findAll();

    @Select("SELECT * FROM `user` WHERE username = #{username}")
    User findById(@Param("username") String username);

    @Select("SELECT * FROM `user` WHERE username = #{username} AND password = #{password}")
    User findOne(@Param("username") String username, @Param("password") String password);


}
