package org.alfresco.httpclient;

import org.apache.http.HttpResponse;

@SuppressWarnings("serial")
public class AuthenticationException extends Exception
{
	private HttpResponse method;

	public AuthenticationException(HttpResponse method)
	{
		this.method = method;
	}

	public HttpResponse getMethod()
	{
		return method;
	}

}
