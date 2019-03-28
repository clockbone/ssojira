package com.clock.sso.jira;

import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
/*import com.atlassian.jira.web.ServletContextProvider;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.LoginReason;
import com.atlassian.seraph.config.SecurityConfig;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggerFactory;
import org.jasig.cas.client.integration.atlassian.Jira7CasAuthenticator;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Map;*/

/**
 * @author: jun_qin
 * @create: 2019/3/28 14:06
 **/
public class JiratestCasAuthenticator extends JiraSeraphAuthenticator {

    /*private static final long serialVersionUID = -8262305967991752189L;
    private static final Logger LOGGER =  LoggerFactory(Jira7CasAuthenticator.class);
    private Cas20ProxyReceivingTicketValidationFilter validationFilter;

    public JiratestCasAuthenticator() {
    }

    @Override
    public void init(Map<String, String> params, SecurityConfig config) {
        super.init(params, config);

        try {
            this.validationFilter = new Cas20ProxyReceivingTicketValidationFilter();
            this.validationFilter.init(new Jira7CasAuthenticator.WrappedFilterConfig(params));
            this.validationFilter.setRedirectAfterValidation(false);
        } catch (ServletException var4) {
            LOGGER.error("Failed to initialize internal validation filter!", var4);
            this.validationFilter = null;
        }

    }

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

    public boolean logout(HttpServletRequest request, HttpServletResponse response) throws AuthenticatorException {
        HttpSession session = request.getSession();
        Principal p = (Principal)session.getAttribute("seraph_defaultauthenticator_user");
        if (p != null) {
            LOGGER.debug("Logging out [{}] from CAS.", p.getName());
        }

        session.setAttribute("_const_cas_assertion_", (Object)null);
        return super.logout(request, response);
    }

    private Principal getUserFromSessionOrAssertion(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Principal existingUser = this.getUserFromSession(request);
            if (existingUser != null) {
                LOGGER.debug("Session found; user already logged in.");
                return existingUser;
            }

            Assertion assertion = (Assertion)session.getAttribute("_const_cas_assertion_");
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

        public WrappedFilterConfig(Map<String, String> var1) {
            this.params = ImmutableMap.copyOf(params);
        }

        public String getFilterName() {
            return null;
        }

        public ServletContext getServletContext() {
            return ServletContextProvider.getServletContext();
        }

        public String getInitParameter(String name) {
            return (String)this.params.get(name);
        }

        public Enumeration<String> getInitParameterNames() {
            return Iterators.asEnumeration(this.params.keySet().iterator());
        }
    }*/
}
