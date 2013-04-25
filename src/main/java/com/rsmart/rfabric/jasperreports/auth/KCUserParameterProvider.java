package com.rsmart.rfabric.jasperreports.auth;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.context.SecurityContextHolder;

import com.jaspersoft.jasperserver.api.common.domain.ExecutionContext;
import com.jaspersoft.jasperserver.api.engine.common.service.BuiltInParameterProvider;
import com.jaspersoft.jasperserver.api.engine.jasperreports.util.JRQueryExecuterAdapter;

public class KCUserParameterProvider implements BuiltInParameterProvider {

  private static final Log LOG = LogFactory.getLog(KCUserParameterProvider.class);

  public static final String          KCID = "KCID";
  public static final String          ISPI = "ISPI";

	public List<Object[]> getParameters(ExecutionContext context,
	   List jrParameters, Map parameters) {
	  
	  LOG.debug("getParameters called");
	  List<Object[]> userProfileParameters = new ArrayList<Object[]>();

    for (String parameterName : new String[] { KCID, ISPI } ) {
        Object[] result = getParameter(context, jrParameters, parameters, parameterName);
        if (result != null) {
            userProfileParameters.add(result);
        }
    }

    return userProfileParameters;
	}

	public Object[] getParameter(ExecutionContext context, List jrParameters,
	   Map parameters, String name) {
	  LOG.debug("getParameter called");
	  
	  Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !(auth.getPrincipal() instanceof AuthTokenAuthentication)) {
        return null;
    }
    
    AuthToken token = (AuthToken) auth.getCredentials();
    
	  if (name.equalsIgnoreCase(KCID)) {
      return new Object[] {JRQueryExecuterAdapter.makeParameter(name, String.class),
          token.getName() != null ? token.getName() : ""};
    } else if (name.equalsIgnoreCase(ISPI)) {
        return new Object[] {JRQueryExecuterAdapter.makeParameter(name, Boolean.class),
          new Boolean(token.isPI())};
    }
	  
		return null;
	}

}
