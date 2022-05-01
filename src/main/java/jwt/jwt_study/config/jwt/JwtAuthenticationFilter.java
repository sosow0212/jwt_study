package jwt.jwt_study.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jwt.jwt_study.config.auth.PrincipalDetails;
import jwt.jwt_study.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// /login 으로 요청해서 username, password를 전송하면 (post)
// UsernamePasswordAuthenticationFilter 가 동작을한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;


    // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 1. username, password 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper(); // JSON 형식을 파싱
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // 토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            // authentication 객체가 session 영역에 저장해야하고, 그 방법이 return해주면 됨
            // return의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는것임.
            // jwt 토큰을 사용하면서 굳이 세션을 만들 이유는 없음. 단지 권한 처리 때문에 session 넣어줌
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("2=============================================");

        // 2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도를 하면,
        // PrincipalDetailsService가 호출된다. 그리고 loadUserByUsername() 함수가 실행된다.

        // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해서)

        // 4. JWT토큰을 만들어서 응답해주면 된다.
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    // jwt토큰을 만들어서 request요청한 사용자에게 Jwt토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증 완료");
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
