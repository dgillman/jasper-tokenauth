package com.rsmart.rfabric.jasperreports.auth;

import java.security.InvalidKeyException;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.util.StringUtils;

/**
 * Implements the AuthenticationProvider interface from the Spring Framework Security
 * specification to enable proxy authentication of a user to JasperReports Server by 
 * a client service using AuthTokens. This provider will analyze AuthTokenAuthentication 
 * objects to determine if they contain a valid AuthToken credential. Validation is 
 * accomplished by generating am HMAC from the name and the nonce contained in the 
 * AuthToken credential, using a secret key shared with the client service at configuration
 * time. If the generate HMAC equals the hash contained in the AuthToken the token is
 * deemed valid.
 * 
 * Next an ExternalUserProvider is checked to determine if the user name is recognized.
 * If so the same ExternalUserProvider is queried for GrantedAuthorities for that user.
 * GrantedAuthorities are simply role names recognized by the JasperReports Server which
 * the user fills.
 * 
 * 
 * client service
 * @author duffy
 *
 */
public class AuthTokenAuthenticationProvider implements AuthenticationProvider {
  private static final Log LOG = LogFactory.getLog(AuthTokenAuthenticationProvider.class);

  private static long						             DFT_TIMEOUT = 60000l;
  
  protected transient Signature 			       signature = new Signature();
  protected transient String 				         secret = null;
  protected transient ExternalUserProvider 	 userProvider = null;
  protected transient String 				         singleUser = null;
  protected transient GrantedAuthority[]	   singleUserAuthorities = null;
  protected transient long					         timeout = DFT_TIMEOUT;
  
  public AuthTokenAuthenticationProvider () {}
  
  public AuthTokenAuthenticationProvider (final String secret) {
    this.secret = secret;
  }
  
  public void setSecret (final String secret) {
    this.secret = secret;
  }
  
  public void setExternalUserProvider (final ExternalUserProvider provider) {
    this.userProvider = provider;
  }
  
  public void setSingleUser (final String user) {
  	LOG.info("singleUser set to \"" + user + "\"; all successfully authenticated tokens will log in as this user");
  	this.singleUser = user;
  }
  
  public void setSingleUserAuthorities (final String authorities[]) {

  	if (LOG.isInfoEnabled()) {
  	  StringBuilder sb = new StringBuilder();
  	  String delim = "";
  	  for (String authority : authorities) {
    		sb.append(delim).append(authority);
    		delim = ", ";
  	  }
  	  LOG.info("singleUserAuthorities set to [" + sb.toString() + 
  				"] - all users will have these authorities");
  	}
  	
  	singleUserAuthorities = new GrantedAuthority[authorities.length];
  	for (int i = 0; i < authorities.length; i++) {
        final String authStr = authorities[i];
  	  singleUserAuthorities[i] = new GrantedAuthority() {
    		private String authority = authStr;
    		
    		public int compareTo(Object o) {
    		  GrantedAuthority that = (GrantedAuthority)o;
              return getAuthority().compareTo(that.getAuthority());
    		}
    
    		public String getAuthority() {
    		  return authority;
    		}		
  	  };
  	}
  }
  
  public void setTimeout (long timeout) {
    this.timeout = timeout;
  }
  
  protected boolean hasTimedOut(final AuthToken token) {
	final long now = (new Date()).getTime();
	final long tokenTime = token.getTimestamp().getTime();
	
	return (now - tokenTime) > timeout;
  }
  
  public Authentication authenticate(final Authentication authn)
      throws AuthenticationException {
    
    if (secret == null || "".equals(secret)) {
      LOG.error("sharedSecret is empty");
      throw new IllegalStateException("sharedSecret == null || empty");
    }

    if (!supports(authn.getClass()) || authn == null) {
      throw new IllegalArgumentException ("Expecting AuthTokenAuthentication object as argument");
    }

    final AuthTokenAuthentication authentication = (AuthTokenAuthentication) authn;

    if (authentication.isAuthenticated()) {
      return authentication;
    }
    
    final AuthToken authToken = (AuthToken) authentication.getCredentials();

    if (hasTimedOut(authToken)) {
      LOG.warn("Token has timed out: " + authToken.toString());
      authn.setAuthenticated(false);
      return null;
    }
    
    final String name = authToken.getName();
    
    try {
      if (singleUser == null && userProvider != null && !userProvider.userExists(name)) {
        LOG.error("User does not exist for token " + authToken);
        authn.setAuthenticated(false);
        return authn;
      }
    } catch (Exception e) {
      LOG.error ("ExternalUserProvider [" + userProvider.getClass() + "] threw an internal error in userExists()", e);
      throw new IllegalStateException ("ExternalUserProvider failed on call to userExists()", e);
    }
    
    try {
      //validate the hash
      final String message = authToken.getHashableFields();
      final String hmac = signature.calculateRFC2104HMACWithEncoding(message, secret, true);
      if (hmac.equals(authToken.getHash())) {
        LOG.debug("token is valid");
        // the user is Ok, we will trust it.
        if (singleUser == null) {
          authentication.setName(name);
        } else {
          authentication.setName(singleUser);
        }
        
        if (singleUserAuthorities != null && singleUserAuthorities.length > 0) {
          authentication.setAuthorities(singleUserAuthorities);
        } else {
          authentication.setAuthorities(userProvider.getAuthoritiesForUser(name));
        }
        return authentication;
      } else {
        LOG.warn("invalid token: " + authToken);
      }
    } catch (InvalidKeyException ike) {
      LOG.error ("Failed to validate token: " + authToken, ike);
      throw new IllegalStateException ("Invalid key used for hashing", ike);
    }
    
    return null;
  }

  @SuppressWarnings("rawtypes")
  public boolean supports(Class authTokenClass) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("supports(\"" + authTokenClass.getName() + "\") reports: " +
          AuthTokenAuthentication.class.isAssignableFrom(authTokenClass));      
    }
    return (AuthTokenAuthentication.class.isAssignableFrom(authTokenClass));
  }

}
