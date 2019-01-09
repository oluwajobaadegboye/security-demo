package com.example.securitydemo.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configuration
@EnableWebSecurity
public class MySec extends WebSecurityConfigurerAdapter {

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder authenticationMgr) throws Exception {
        authenticationMgr.inMemoryAuthentication().passwordEncoder(passwordEncoder)
                .withUser("joba").password("{noop}joba@123").authorities("ROLE_USER")
                .and()
                .withUser("admin").password("{noop}joba@123").authorities("ROLE_USER","ROLE_ADMIN")
                .and()
                .withUser("bcUser").password("$2a$10$xNmpDwTYgrMlB5lG0RbI/u1azayb/ds2QZwbchg//WReOW3vCQ4iu").authorities("ROLE_USER","ROLE_ADMIN");

//                User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build();
//        authenticationMgr.inMemoryAuthentication().passwordEncoder(NoOpPasswordEncoder.getInstance())
//                .withUser("test").password("test123").roles("USER").and()
//                .withUser("test1").password("test123").roles("ADMIN");


    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/version").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/greeting").access("hasRole('ROLE_ADMIN')")
                .and()
                .formLogin()
                .defaultSuccessUrl("/greeting");
    }
}
