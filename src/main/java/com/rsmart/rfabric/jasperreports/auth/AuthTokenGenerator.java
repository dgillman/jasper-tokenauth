package com.rsmart.rfabric.jasperreports.auth;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Date;

/** This is a commandline utility for generating tokens */
public class AuthTokenGenerator {

  /**
   * @param args
   */
  public static void main(String[] args) {
    if (args.length < 3) {
      System.out.println("Usage:\n\tjava " + AuthTokenGenerator.class.getName() + " <shared secret> <user> <is PI: true/false>");
      System.exit(1);
    }
    if (args.length > 3) {
      System.err.println ("Extra command line arguments ignored");
    }
    
    final String secret = args[0];
    final String user = args[1];
    final boolean ispi = Boolean.parseBoolean(args[2]);
    
    final Signature signature = new Signature();
    final SecureRandom rand = new SecureRandom();
    final int nonce = rand.nextInt();
    final String toSign = user + AuthToken.TOKEN_SEPARATOR + args[2] + AuthToken.TOKEN_SEPARATOR 
        + (new Date()).getTime() + AuthToken.TOKEN_SEPARATOR + nonce;
    final String hmac;
    try {
      hmac = signature.calculateRFC2104HMACWithEncoding(toSign, secret, true);
      System.out.println (hmac + AuthToken.TOKEN_SEPARATOR + toSign);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      System.exit(0);
    }
    
  }

}
