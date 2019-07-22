package com.zjcy.sso.common.core.cas;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AbstractAccessDecisionManager;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
/*控制 是不是让进入系统*/
public class MyAccessDecisionManager extends AbstractAccessDecisionManager {


    public MyAccessDecisionManager(List<AccessDecisionVoter<? extends Object>> decisionVoters) {
        super(decisionVoters);
    }


    /**
     * @param authentication   UserService 权限信息集合
     * @param object           equset message
     * @param configAttributes MyMetadataSourceService
     * @throws AccessDeniedException,InsufficientAuthenticationException,BadCredentialsException 加入权限表后，则返回给 decide 方法 其它情况 不做控制
     */
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException, InsufficientAuthenticationException, BadCredentialsException, DisabledException {


        if (authentication instanceof AnonymousAuthenticationToken) {
            throw new BadCredentialsException("未登录");
        }

        if (null == configAttributes || configAttributes.size() == 0) {
            return;
        }

        for (Iterator<ConfigAttribute> iter = configAttributes.iterator(); iter.hasNext(); ) {
            ConfigAttribute configAttribute = iter.next();
            String permcode = configAttribute.getAttribute();
            if ("YOU_NEED_PORM".equals(permcode)) {
                throw new AccessDeniedException("no perm");
            }

            for (GrantedAuthority ga : authentication.getAuthorities()) {
                if (permcode.trim().equals(ga.getAuthority())) {
                    return;
                }
            }
        }


        throw new AccessDeniedException("no perm");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
