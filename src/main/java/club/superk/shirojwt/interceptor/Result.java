package club.superk.shirojwt.interceptor;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Result {

    // 状态码
    private int code;
    // 返回信息
    private String msg;
    // 返回数据
    private Object data;

    public Result(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}
