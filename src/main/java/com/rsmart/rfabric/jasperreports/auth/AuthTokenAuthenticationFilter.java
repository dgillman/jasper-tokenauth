package com.rsmart.rfabric.jasperreports.auth;

import com.jaspersoft.jasperserver.api.metadata.xml.domain.impl.OperationResult;
import com.jaspersoft.jasperserver.remote.ServicesUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.ProviderManager;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.List;

/**
 * Implements a Servlet filter which extracts an AuthToken from an HTTP header or a CGI
 * parameter. If the AuthToken is found an AuthTokenAuthentication object is constructed
 * and is passed to the Spring Security AuthenticationManager to handle authentication.
 */
public class AuthTokenAuthenticationFilter implements Filter, ApplicationContextAware  {

    private static final Log log = LogFactory.getLog(AuthTokenAuthenticationFilter.class);
    
    public static final String AUTH_TOKEN_HEADER = "x-authn-token";
    public static final String AUTH_TOKEN_PARAM = "authntoken";

    private static ApplicationContext applicationContext = null;
    private static ServicesUtils servicesUtils = null;
    
    private AuthenticationManager authenticationManager;

    public void destroy() {
    }
    
    /**
     * Simply grab the authentication token from the request. Does not validate
     * results; i.e. raw data retrieval from request.
     * 
     * @param request
     * @return token
     * @throws IllegalArgumentException
     */
    @SuppressWarnings("unchecked")
    public final AuthToken getToken (final HttpServletRequest request) {
      log.debug("getToken(final HttpServletRequest request)");
      if (request == null) {
        throw new IllegalArgumentException("request == null");
      }
      
      if (log.isTraceEnabled()) {
        StringBuilder sb;
        String delim;
        Enumeration<String> names;
        
        sb = new StringBuilder();
        names = request.getHeaderNames();
        delim = "";
        while (names.hasMoreElements()) {
          sb.append(delim);
          sb.append(names.nextElement());
          delim=", ";
        }
        log.trace("headers: " + sb.toString());
        
        sb = new StringBuilder();
        names = request.getParameterNames();
        delim = "";
        while (names.hasMoreElements()) {
          sb.append(delim);
          sb.append(names.nextElement());
          delim=", ";
        }
        log.trace("params: " + sb.toString());
      }
      String token = request.getHeader(AUTH_TOKEN_HEADER);
      
      if (token == null) {
        token = request.getParameter(AUTH_TOKEN_PARAM);
        if (token != null) {
          log.debug ("token passed as request parameter " + AUTH_TOKEN_PARAM);
        }
      } else {
        log.debug ("token passed as request header " + AUTH_TOKEN_HEADER);
      }
      if (token == null) {
        log.debug("no authentication token found");
        return null;
      }
      
      log.debug("retrieved authentication token: " + token);
      return new AuthToken (token);
    }

    /**
     * Intercepts HTTP traffic to look for AuthToken headers. If one exists authentication occurs
     * otherwise the request is passed on.
     */
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
        throws IOException, ServletException {

   	  final HttpServletRequest request = (HttpServletRequest) servletRequest;
      final HttpServletResponse response = (HttpServletResponse) servletResponse;

      //create credentials
      AuthToken credential = getToken(request);
    	
      if(credential == null) {
    	  chain.doFilter(servletRequest, servletResponse);
    	  return;
      }

      log.debug("request has an AuthToken - attempting to authenticate");
    	
      //create Authentication object
      AuthTokenAuthentication authentication = new AuthTokenAuthentication(credential);

      //call authenticationManager.authenticate
      Authentication authResult;
      try {
        authResult = authenticationManager.authenticate(authentication);
      } catch (AuthenticationException e) {
        if (log.isDebugEnabled()) {
          log.debug("Token " + credential + " failed to authenticate: " + e.toString());
        }
        if (log.isWarnEnabled()) {
          log.warn("Token " + credential + " failed to authenticate: " + e.toString() + " " + e, e.getRootCause());
        }

        SecurityContextHolder.getContext().setAuthentication(null);

        // Send an error message in the form of OperationResult...
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        OperationResult or = servicesUtils.createOperationResult(1, "Failed authentication for token " + credential);
        PrintWriter pw = response.getWriter();
        pw.print("Unauthorized");
        return;
      }

      if (log.isDebugEnabled()) {
        log.debug("User " + authentication.getName() + " authenticated: " + authResult);
      }

      SecurityContextHolder.getContext().setAuthentication(authResult);

      chain.doFilter(request, response);
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        
        if (log.isDebugEnabled() && authenticationManager instanceof ProviderManager) {
          StringBuffer buff = new StringBuffer();
          buff.append("AuthenticationProviders:\n");
          ProviderManager pm = (ProviderManager)authenticationManager;
          List<AuthenticationProvider> providers = pm.getProviders();
          for (AuthenticationProvider provider : providers) {
            buff.append("\t").append(provider.getClass().toString()).append("\n");
          }
          log.debug(buff.toString());
        }
    }

    public void setApplicationContext(ApplicationContext ac) throws BeansException {
        applicationContext = ac;
        servicesUtils = ac.getBean(ServicesUtils.class);
    }
    
    public void init(FilterConfig fc) throws ServletException {
    }

}
