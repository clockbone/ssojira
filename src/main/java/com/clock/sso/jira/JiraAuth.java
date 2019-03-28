package com.clock.sso.jira;


import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import com.atlassian.jira.web.ServletContextProvider;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.LoginReason;
import com.atlassian.seraph.config.SecurityConfig;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterators;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Map;

/**
 * @author: jun_qin
 * @create: 2019/3/26 14:14
 **/
public class JiraAuth extends JiraSeraphAuthenticator {

    //private static final Logger log = Logger.getLogger(JiraAuth.class);

    private static final Logger LOGGER = LoggerFactory.getLogger(JiraAuth.class);

    private Cas20ProxyReceivingTicketValidationFilter validationFilter;

    public JiraAuth() {
    }

    @Override
    public void init(Map<String, String> params, SecurityConfig config) {
        System.out.println("init 初始化参数prams:" + params);
        System.out.println("init 初始化参数SecurityConfig:getAuthType" + config.getAuthType());
        System.out.println("init 初始化参数SecurityConfig:getLinkLoginURL" + config.getLinkLoginURL());
        System.out.println("init 初始化参数SecurityConfig:getLoginCookieKey" + config.getLoginCookieKey());
        System.out.println("init 初始化参数SecurityConfig:getLoginCookiePath" + config.getLoginCookiePath());
        System.out.println("init 初始化参数SecurityConfig:getLoginURL" + config.getLoginURL());
        System.out.println("init 初始化参数SecurityConfig:getOriginalURLKey" + config.getOriginalURLKey());

        super.init(params, config);

        try {
            this.validationFilter = new Cas20ProxyReceivingTicketValidationFilter();
            this.validationFilter.init(new JiraAuth.WrappedFilterConfig(params));
            this.validationFilter.setRedirectAfterValidation(false);
        } catch (ServletException var4) {
            System.out.println("Failed to initialize internal validation filter!" + var4);
            this.validationFilter = null;
        }

    }

    @Override
    public boolean logout(HttpServletRequest request, HttpServletResponse response) throws AuthenticatorException {
        System.out.println("登出方法");
        HttpSession session = request.getSession();
        Principal p = (Principal) session.getAttribute("seraph_defaultauthenticator_user");
        if (p != null) {
            System.out.println("Logging out [{}] from CAS." + p.getName());
        }

        session.setAttribute("_const_cas_assertion_", (Object) null);
        return super.logout(request, response);
    }


    @Override
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Principal existingUser = this.getUserFromSessionOrAssertion(request, response);
            if (existingUser != null) {
                return existingUser;
            }
        }

        if (response != null) {
            try {
                this.validationFilter.doFilter(request, response, new FilterChain() {
                    @Override
                    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                    }
                });
                return this.getUserFromSessionOrAssertion(request, response);
            } catch (Exception var5) {
                LOGGER.debug("Call to internal validation filter failed", var5);
            }
        }

        return null;
    }

    private Principal getUserFromSessionOrAssertion(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Principal existingUser = this.getUserFromSession(request);
            if (existingUser != null) {
                LOGGER.debug("Session found; user already logged in.");
                return existingUser;
            }

            Assertion assertion = (Assertion) session.getAttribute("_const_cas_assertion_");
            if (assertion != null) {
                String username = assertion.getPrincipal().getName();
                Principal user = this.getUser(username);
                if (user != null) {
                    this.putPrincipalInSessionContext(request, user);
                    this.getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, username);
                    LoginReason.OK.stampRequestResponse(request, response);
                    LOGGER.debug("Logging in [{}] from CAS.", username);
                } else {
                    LOGGER.debug("Failed logging [{}] from CAS.", username);
                    this.getElevatedSecurityGuard().onFailedLoginAttempt(request, username);
                }

                return user;
            }
        }

        return null;
    }

    private class WrappedFilterConfig implements FilterConfig {
        private final Map<String, String> params;

        public WrappedFilterConfig(Map<String, String> params) {
            this.params = ImmutableMap.copyOf(params);
        }

        @Override
        public String getFilterName() {
            return null;
        }

        @Override
        public ServletContext getServletContext() {
            return ServletContextProvider.getServletContext();
        }

        @Override
        public String getInitParameter(String name) {
            return (String) this.params.get(name);
        }

        @Override
        public Enumeration<String> getInitParameterNames() {
            return Iterators.asEnumeration(this.params.keySet().iterator());
        }
    }
}
