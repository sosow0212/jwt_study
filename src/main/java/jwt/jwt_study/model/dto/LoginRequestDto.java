package jwt.jwt_study.model.dto;

import lombok.Data;
@Data
public class LoginRequestDto {
    private String username;
    private String password;
}