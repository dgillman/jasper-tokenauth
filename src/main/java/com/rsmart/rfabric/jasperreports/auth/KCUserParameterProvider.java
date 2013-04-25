package com.rsmart.rfabric.jasperreports.auth;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import net.sf.jasperreports.engine.JRParameter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.context.SecurityContextHolder;

import com.jaspersoft.jasperserver.api.common.domain.ExecutionContext;
import com.jaspersoft.jasperserver.api.engine.common.service.BuiltInParameterProvider;
import com.jaspersoft.jasperserver.api.engine.jasperreports.util.JRQueryExecuterAdapter;
import com.jaspersoft.jasperserver.api.metadata.user.domain.impl.client.MetadataUserDetails;

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
	  LOG.debug("getParameter called for param '" + name + "'");
	  AuthToken token = null;
	  
	  Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null && auth.getPrincipal() instanceof MetadataUserDetails) {
      MetadataUserDetails userDetails = (MetadataUserDetails)auth.getPrincipal();
      Authentication origAuth = userDetails.getOriginalAuthentication();
      
      if (origAuth != null && origAuth instanceof AuthTokenAuthentication) {
        token = (AuthToken) ((AuthTokenAuthentication)origAuth).getCredentials();
      }
    }

    if (token == null) {
      LOG.warn("User has not authenticated with a token from KC - no KC ID or isPI flag will be available");
      return null;
    }
    
    JRParameter param = null;
    Object value = null;
    
	  if (name.equalsIgnoreCase(KCID)) {
	    LOG.trace("KCID parameter requested");
	    param = JRQueryExecuterAdapter.makeParameter(name, String.class);
      value = token.getName() != null ? token.getName() : "";
    } else if (name.equalsIgnoreCase(ISPI)) {
      LOG.trace("ISPI parameter requested");
      param = JRQueryExecuterAdapter.makeParameter(name, Boolean.class);
      value = new Boolean(token.isPI());
    }
	  
    if ( param != null && value != null ) {
      LOG.trace("returning param: " + param.toString() + " value: " + value.toString());
      return new Object[] { param, value };
    }
		return null;
	}

}