package com.rsmart.rfabric.jasperreports.auth.kim.servicefactory;

import java.net.MalformedURLException;
import java.net.URL;

import org.kuali.rice.kim.v2_0.IdentityService_Service;

public class IdentityServiceFactory extends ServiceFactory<IdentityService_Service> {
	public IdentityService_Service instantiateService() {
		try {
			return new IdentityService_Service(new URL(getWsdlUrl()));
		} catch (MalformedURLException mue) {
			throw new RuntimeException ("Failed to instantiate IdentityService_Service", mue);
		}
	}
}
