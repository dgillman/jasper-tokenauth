jasper-tokenauth
================

Implements Spring Security classes to permit server-to-server proxy token
authentication to JasperReports Server.

Build Instructions
------------------

* Download and unzip [JasperReports 4.7.0 Source](http://community.jaspersoft.com/sites/default/files/releases/jasperreports-server-4.7.0-src.zip). Record the location to which you have unzipped the source. I will refer to that directory as $JASPER_SRC.

* Using Maven 3.0 or greater, build this project with the following command:
  ```mvn -Djasperserver-repo=$JASPER_SRC/jasperserver-repo clean install```

Install Instructions
--------------------

* Build this project with the instructions above.

* Download and install [JasperReports Server](http://community.jaspersoft.com/project/jasperreports-server/releases).

* Edit ```src/main/deployfiles/applicationContext.xml``` to set the secret key
in the ```authTokenAuthenticationProvider``` bean (this MUST match the key used in the client application)

* Deploy the configuration files to Jasper Reports Server:

  ```cp src/main/deployfiles/* /Applications/jasperreports-server-cp-4.7.0/apache-tomcat/webapps/jasperserver/WEB-INF```

* Deploy the jar file to Jasper Reports Server:

  ```cp target/*.jar /Applications/jasperreports-server-cp-4.7.0/apache-tomcat/webapps/jasperserver/WEB-INF/lib```

* Start (or restart) the Jasper Reports Server
