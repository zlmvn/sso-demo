package com.zjcy.sso.common.core.cas;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
/*加载现有资源 url*/
@Service
public class MyMetadataSourceService implements
        FilterInvocationSecurityMetadataSource {

    /**
     * 加载权限表中所有权限
     */
    public Map loadResourceDefine() {

        Map map = new HashMap();
        List<String> ls = new ArrayList<>();

        ls.add("/");
        ls.add("/hello");
        ls.add("/authorize");
        ls.add("/error");

        for (String s : ls) {
            ArrayList array = new ArrayList<>();
            array.add(new SecurityConfig(s));
            map.put(s, array);
        }
        return map;

    }

    /**
     * 在权限中的会执行  decide
     *
     * @param object xx
     * @return xx
     * @throws IllegalArgumentException xx
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {


        Map<String, Collection<ConfigAttribute>> map = loadResourceDefine();

        HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
        AntPathRequestMatcher matcher;
        String resUrl;

        for (Iterator<Map.Entry<String, Collection<ConfigAttribute>>> iter = map.entrySet().iterator(); iter.hasNext(); ) {
            Map.Entry<String, Collection<ConfigAttribute>> me = iter.next();
            resUrl = me.getKey();
            matcher = new AntPathRequestMatcher(resUrl);
            if (matcher.matches(request)) {
                return me.getValue();
            }
        }
        return SecurityConfig.createList("YOU_NEED_PORM");

    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

}
