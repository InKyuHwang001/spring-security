package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //적용 url
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );
        //로그인  커스텀
        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc")
                        .permitAll()
                );
        ////Http Basic 인증 방식
//        http
//                .httpBasic(Customizer.withDefaults());
        //세션 설정
        ////다중 로그인
        http
                .sessionManagement((auth) -> auth
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true)); //true : 초과시 새로운 로그인 차단 //false : 초과시 기존 세션 하나 삭제
        ////섹션 고정 보호
        http
                .sessionManagement((auth) -> auth
                        .sessionFixation().changeSessionId());
        //- sessionManagement().sessionFixation().none() : 로그인 시 세션 정보 변경 안함
        //- sessionManagement().sessionFixation().newSession() : 로그인 시 세션 새로 생성
        //- sessionManagement().sessionFixation().changeSessionId() : 로그인 시 동일한 세션에 대한 id 변경

        //csrf : 요청을 위조하여 사용자 모르게 보네는 것 eg 회원 정보 변경, 게시글 CRUD를 사용자 모르게 요청
        http
                .csrf((auth) -> auth.disable());
        //API 서버의 경우 csrf.disable()
        // 앱에서 사용하는 API 서버의 경우 보통 세션을 STATELESS로 관리하기 때문에
        // 스프링 시큐리티 csrf enable 설정을 진행하지 않아도 된다.
        return http.build();
    }

    //Role Hierarchy
    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_C > ROLE_B\n" +
                "ROLE_B > ROLE_A");

        return hierarchy;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }
}
