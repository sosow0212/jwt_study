package jwt.jwt_study;

import lombok.Data;
@Data
public class LoginRequestDto {
    private String username;
    private String password;
}