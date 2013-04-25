package com.rsmart.rfabric.jasperreports.auth;

import java.security.InvalidKeyException;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.AuthenticationProvider;

/**
 * Implements the AuthenticationProvider interface from the Spring Framework Security
 * specification to enable proxy authentication of a user to JasperReports Server by 
 * a client service using AuthTokens. This provider will analyze AuthTokenAuthentication 
 * objects to determine if they contain a valid AuthToken credential. Validation is 
 * accomplished by generating am HMAC from the name, isPI flag, a timestamp, and a nonce
 * contained in the AuthToken credential. The HMAC is calculated using a secret key 
 * shared with the client service at configuration time. If the generated HMAC equals 
 * the hash contained in the AuthToken the token is deemed valid.
 * 
 * The login name used for the authenticated user can be obtained in two ways:
 *   1) If the 'singleUser' variable is set, the login will happen under that user name.
 *     This permits all logins to happen under a special utility account. The Spring
 *     Framework will recognize that user by calling AuthTokenAuthentication.getName().
 *     But the user can still be differentiated for report generation purposed by
 *     by consulting the AuthToken.getName() method.
 *   2) Otherwise, an option 'externalUserProvider' can be registered which will consult
 *     an external resource to resolve that the name supplied is valid. In this case
 *     every user will log in under their own account name. That account must exist in
 *     JasperServer. Both AuthToken.getName() and AuthTokenAuthentication.getName() will
 *     return that same value.
 *     
 * The roles ("GrantedAuthorities") applied to the logged in user similarly can be configured
 * by setting the 'singleUserAuthorities' array, or by registering an 'externalUserProvider'.
 * In both cases the role names which are supplied must match roles that are defined in 
 * the JasperServer.
 * 
 * Tokens will have a timestamp which can be used to expire tokens after some elapsed number
 * of milliseconds. Any token which is older than 'timeout' milliseconds will be considered
 * invalid.
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
  
  @SuppressWarnings("serial")
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
    
    //check to be sure a secret has been configured. without it authentication is impossible
    if (secret == null || "".equals(secret)) {
      LOG.error("sharedSecret is empty");
      throw new IllegalStateException("sharedSecret == null || empty");
    }

    //make sure the authentication object is from our authentication endpoint, not some other login source
    if (!supports(authn.getClass()) || authn == null) {
      throw new IllegalArgumentException ("Expecting AuthTokenAuthentication object as argument");
    }

    final AuthTokenAuthentication authentication = (AuthTokenAuthentication) authn;

    // don't authenticate something that is already authenticated
    if (authentication.isAuthenticated()) {
      return authentication;
    }
    
    final AuthToken authToken = (AuthToken) authentication.getCredentials();

    // check if the timestamp is too old
    if (hasTimedOut(authToken)) {
      LOG.warn("Token has timed out: " + authToken.toString());
      authn.setAuthenticated(false);
      return null;
    }
    
    final String name = authToken.getName();
    
    try {
      // check for a valid source of user identity
      if (singleUser == null && userProvider != null && !userProvider.userExists(name)) {
        LOG.error("User does not exist for token " + authToken);
        authn.setAuthenticated(false);
        return null;
      }
    } catch (Exception e) {
      // this most likely means the userProvider did something dumb
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
          // not using 'singleUser', so login as the name provided
          authentication.setName(name);
        } else {
          // using 'singleUser' so login as that user. The name supplied in the token can still be used to differentiate users
          authentication.setName(singleUser);
        }
        
        if (singleUserAuthorities != null && singleUserAuthorities.length > 0) {
          // use the GrantedAuthority names supplied for all users
          authentication.setAuthorities(singleUserAuthorities);
        } else {
          // consult the user provider
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
