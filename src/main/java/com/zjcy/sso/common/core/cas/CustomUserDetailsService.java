package com.zjcy.sso.common.core.cas;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;
/*
*
*当前登录用户所拥有的权限
* */
public class CustomUserDetailsService implements AuthenticationUserDetailsService {


    @Override
    public UserDetails loadUserDetails(Authentication authentication) throws UsernameNotFoundException {
        System.out.println("当前的用户名是：" + authentication.getName());
        /*这里我为了方便，就直接返回一个用户信息，实际当中这里修改为查询数据库或者调用服务什么的来获取用户信息*/
        MyUserDetails userInfo = new MyUserDetails();
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("/");
        GrantedAuthority grantedAuthority2 = new SimpleGrantedAuthority("/hello");
        GrantedAuthority grantedAuthority3 = new SimpleGrantedAuthority("/authorize");
        GrantedAuthority grantedAuthority4 = new SimpleGrantedAuthority("/error");

        grantedAuthorities.add(grantedAuthority);
        grantedAuthorities.add(grantedAuthority2);
        grantedAuthorities.add(grantedAuthority3);
        grantedAuthorities.add(grantedAuthority4);
        userInfo.setAuthorities(grantedAuthorities);
        return userInfo;
    }
}
