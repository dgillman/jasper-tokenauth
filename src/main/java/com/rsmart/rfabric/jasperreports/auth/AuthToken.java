package com.rsmart.rfabric.jasperreports.auth;

import java.util.Date;

/**
 * Represents an authorization token sent in an HTTP request. The token will be composed of
 * a user name, a boolan isPI flag ("is principal investigator"), a timestamp, a random 
 * string (a 'nonce'), and a hash.
 * 
 * @author duffy
 */
public class AuthToken {
  
  public static final String TOKEN_SEPARATOR = ";";

  private String 	token = null;
  private String 	hash = null;
  private String 	name = null;
  private boolean	isPI = false;
  private Date 		timestamp = null;
  private String 	nonce = null;
  
  /**
   * Parses a token string of the form [hash];[name];[isPI];[timestamp];[nonce] into its 
   * component parts.
   * 
   * Throws an IllegalArgumentException if the token is malformed.
   * 
   * @param token
   */
  public AuthToken (final String token) {
    if (token == null || token.isEmpty()) {
      throw new IllegalArgumentException ("token is empty");
    }
    
    this.token = token;
    
    final String parts[] = token.split(TOKEN_SEPARATOR);
    if (parts == null || parts.length != 5) {
      throw new IllegalArgumentException ("malformed token");
    }
    
    hash 		= parts[0];
    name 		= parts[1];
    isPI 		= Boolean.parseBoolean(parts[2]);
    timestamp 	= new Date(Long.parseLong(parts[3]));
    nonce 		= parts[4];
  }
  
  public String getHash() {
    return hash;
  }
  
  public String getName() {
    return name;
  }
  
  public boolean isPI() {
    return isPI;
  }
  
  public Date getTimestamp() {
	return timestamp;
  }
  
  public String getNonce() {
    return nonce;
  }
 
  public String getHashableFields() {
	StringBuilder sb = new StringBuilder();
	
	sb.append(name).append(TOKEN_SEPARATOR).append(Boolean.toString(isPI))
	  .append(TOKEN_SEPARATOR).append(timestamp.getTime()).append(TOKEN_SEPARATOR).append(nonce);
	
	return sb.toString();
  }
  
  public String toString() {
    return token;
  }

}