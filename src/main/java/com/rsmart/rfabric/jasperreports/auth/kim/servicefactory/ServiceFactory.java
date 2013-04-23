package com.rsmart.rfabric.jasperreports.auth.kim.servicefactory;

import javax.xml.ws.Service;

public abstract class ServiceFactory<S extends Service> {
	private String wsdlUrl;
	private S service;
	
	public void setWsdlUrl(String url) {
		wsdlUrl = url;
	}
	
	public String getWsdlUrl() {
		return wsdlUrl;
	}
	
	public abstract S instantiateService();
	
	public S getService() {
		if (service == null) {
			service = instantiateService();
		}
		
		return service;
	}
}
