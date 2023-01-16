# Security Filter 예외처리하기 - JWT

Spring Security에서 토큰 기반 인증 중 예외가 발생한다면 어떤 일이 일어나는지, 어떻게 핸들링 해야하는지에 대해 알아보자.



###  이전에 알아야 할 지식

> - 토큰 인증 방식 
>
>   인증받은 사용자에게 토큰을 발급해주고,
>
>   서버에 요청을 할 때 HTTP 헤더에 토큰을 함께 보내 인증받은 사용자(유효성 검사)인지 확인한다.



> - Spring boot 예외처리 방식
>
>   - `@ControllerAdvice`와 `@RestControllerAdvice`를 이용해서 컴포넌트를 생성하고 예외처리 메서드를 작성해놓으면 모든 클래스에 전역적으로 적용이 가능하다. 
>
>   - `@ExceptionHandler`을 통해 특정 컨트롤러의 예외를 처리한다.





### Q. Spring Security에서 토큰을 검증할 경우, 예외가 발생한다면 기존에 사용 중이던 Custom Exception으로 처리가 될까?

A. 가능하다면 좋겠지만 불가능하다!

>  spring security와 spring boot 예외 처리구간이 다르다고 생각해보면 간단하다.
>
>  `Filter`는 `Dispatcher Servlet` 보다 앞단에 존재하며 `Handler Intercepter`는 뒷단에 존재하기 때문에 `Filter` 에서 보낸 예외는 `Exception Handler`로 처리를 못한다.

<img src="C:\Users\wjdtk\AppData\Roaming\Typora\typora-user-images\image-20230116193520004.png" alt="image-20230116193520004" style="zoom:67%;" />

따라서, 토큰 예외처리를 위해선 새로운 Filter를 정의해서 Filter Chain에 추가해줘야 한다.



#### 1. SecurityConfig 클래스 수정

```java
public class SecurityConfig  {
    private final UserService userService;
    @Value("${jwt.token.secret}")
    private String secretKey;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .httpBasic().disable()
                .csrf().disable()
                .cors().and()
                .authorizeRequests()
                .antMatchers("/api/v1/users/join", "/api/v1/users/login").permitAll()
                .antMatchers( "/api/v1/users/list","/api/v1/users/{userId}/role/change").hasAnyRole("ADMIN")
                .antMatchers(HttpMethod.GET,"/api/v1/posts/my", "/api/v1/alarms").authenticated()
                .antMatchers(HttpMethod.POST, "/api/v1/**").authenticated()
                .antMatchers(HttpMethod.PUT, "/api/v1/**").authenticated()
                .antMatchers(HttpMethod.DELETE, "/api/v1/**").authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new CustomAuthenticationEntryPointHandler())
                .accessDeniedHandler(new CustomAccessDeniedHandler())
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(new JwtTokenFilter(userService, secretKey), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new ExceptionHandlerFilter(), JwtTokenFilter.class)
                .build();

    }


```

> `addFilterBefore(Filter, beforeFilter)` 
>
> **beforeFilter**가 실행되기 이전에 **Filter**을 먼저 실행시키도록 설정하는 메소드이다.
>
> ```java
> .addFilterBefore(new JwtTokenFilter(userService, secretKey), UsernamePasswordAuthenticationFilter.class)
> .addFilterBefore(new ExceptionHandlerFilter(), JwtTokenFilter.class)
> ```

> 그 외 추가한 메소드 설명
>
> ```java
> .exceptionHandling()
>     // 인증 과정에서 예외가 발생할 경우 예외를 전달한다.
>                 .authenticationEntryPoint(new CustomAuthenticationEntryPointHandler()) 
>     // 권한을 확인하는 과정에서 통과하지 못하는 예외가 발생하는 경우 예외를 전달한다.
>                 .accessDeniedHandler(new CustomAccessDeniedHandler())





메소드를 살펴보면 `인가 과정의 예외 상황`에서 CustomAccessDeniedHandler와 CustomAuthenticationEntryPointHandler 로 예외를 전달하고 있었다. 

다음은 이러한 클래스를 작성하는 방법이다.



#### 2.  CustomAccessDeniedHandler클래스 생성

```java
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        
        ErrorCode errorCode = ErrorCode.FORBIDDEN_REQUEST;
        JwtTokenFilter.setErrorResponse(response, errorCode);
    }
}
```

>  `AccessDeniedHandler` 
>
> 액세스 권한이 없는 리소스에 접근할 경우 발생하는 예외
>
> handle() 메소드를 오버라이딩한다.



#### 3. CustomAuthenticationEntryPointHandler 클래스 생성

```java
@Slf4j
@Component
public class CustomAuthenticationEntryPointHandler implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.error("토큰이 존재하지 않거나 Bearer로 시작하지 않는 경우");
            ErrorCode errorCode = ErrorCode.INVALID_TOKEN;
            JwtTokenFilter.setErrorResponse(response, errorCode);
        } else if (authorization.equals(ErrorCode.EXPIRED_TOKEN)) {
            log.error("토큰이 만료된 경우");
            ErrorCode errorCode = ErrorCode.EXPIRED_TOKEN;
            JwtTokenFilter.setErrorResponse(response,errorCode);
        }
    }
}

```

> `AuthenticationEntryPoint`
>
> 인증이 실패한 상황을 처리한다.
>
> commence() 메서드를 오버라이딩해서 코드를 구현한다.



#### 5. 그 외

에러코드는 enum으로 관리한다

```java
@AllArgsConstructor
@Getter
public enum ErrorCode {
    
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "잘못된 토큰입니다."),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 토큰입니다."),
    INVALID_PERMISSION(HttpStatus.UNAUTHORIZED, "사용자가 권한이 없습니다."),
    FORBIDDEN_REQUEST(HttpStatus.FORBIDDEN, "ADMIN 회원만 접근할 수 있습니다.");

    private final HttpStatus httpStatus;
    private final String message;
}
```



JwtTokenFilter에 메소드를 추가로 작성해서 가독성을 높였다.

```java
	/**
     * Security Chain 에서 발생하는 에러 응답 구성
     */
    public static void setErrorResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(errorCode.getHttpStatus().value());
        ObjectMapper objectMapper = new ObjectMapper();

        ErrorResponse errorResponse = new ErrorResponse
                (errorCode, errorCode.getMessage());

        Response<ErrorResponse> error = Response.error(errorResponse);
        String s = objectMapper.writeValueAsString(error);

        /**
         * 한글 출력을 위해 getWriter() 사용
         */
        response.getWriter().write(s);
    }

```







### 마무리

시큐리티를 처음 설정할 땐 낯설게 느껴지지만 핵심적인 클래스와 메서드를 짚어보면 큰 그림이 그려진다.

어려운 내용을 만났을 때 잘 모르고 다음으로 넘어가는 것보다 이렇게 하나씩 정리해두면 

두고두고 이용해먹을 수 있겠다.







- 참고 자료

[Security Filter에서 발생하는 Exception 처리하기](https://inkyu-yoon.github.io/docs/Language/SpringBoot/FilterExceptionHandle)

[[Spring Boot] JWT 토큰 만료에 대한 예외처리](https://velog.io/@hellonayeon/spring-boot-jwt-expire-exception)

 [스프링부트핵심가이드](http://www.yes24.com/Product/Goods/110142898)(397~403)