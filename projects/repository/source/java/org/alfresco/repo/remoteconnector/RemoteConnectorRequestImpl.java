/*
 * Copyright (C) 2005-2012 Alfresco Software Limited.
 *
 * This file is part of Alfresco
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */
package org.alfresco.repo.remoteconnector;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.service.cmr.remoteconnector.RemoteConnectorRequest;
import org.alfresco.service.cmr.remoteconnector.RemoteConnectorService;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;

/**
 * Helper wrapper around a Remote Request, to be performed by the
 *  {@link RemoteConnectorService}.
 * 
 * @author Nick Burch
 * @since 4.0.2
 */
public class RemoteConnectorRequestImpl implements RemoteConnectorRequest
{
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    
    private final String url;
    private final String methodName;
    private final HttpRequestBase method;
    Map<String,Header> headers = new HashMap<String,Header>();
    private HttpEntity requestBody;
    
    public RemoteConnectorRequestImpl(String url, String methodName)
    {
        this(url, buildHttpClientMethod(url, methodName));
    }
    public RemoteConnectorRequestImpl(String url, Class<? extends HttpRequestBase> method)
    {
        this(url, buildHttpClientMethod(url, method));
    }
    private RemoteConnectorRequestImpl(String url, HttpRequestBase method)
    {
        this.url = url;
        this.method = method;
        this.methodName = method.getMethod();
    }
    
    protected static HttpRequestBase buildHttpClientMethod(String url, String method)
    {
        if ("GET".equals(method))
        {
            return new HttpGet(url);
        }
        if ("POST".equals(method))
        {
            return new HttpPost(url);
        }
        if ("PUT".equals(method))
        {
            return new HttpPut(url);
        }
        if ("DELETE".equals(method))
        {
            return new HttpDelete(url);
        }
        if (TestingMethod.METHOD_NAME.equals(method))
        {
            return new TestingMethod(url);
        }
        throw new UnsupportedOperationException("Method '"+method+"' not supported");
    }
    protected static HttpRequestBase buildHttpClientMethod(String url, Class<? extends HttpRequestBase> method)
    {
        HttpRequestBase request = null;
        try
        {
            request = method.getConstructor(String.class).newInstance(url);
        }
        catch(Exception e)
        {
            throw new AlfrescoRuntimeException("HttpClient broken", e);
        }
        return request;
    }
    
    public String getURL()
    {
        return url;
    }
    public String getMethod()
    {
        return methodName;
    }
    public HttpRequestBase getMethodInstance()
    {
        return method;
    }
    
    public String getContentType()
    {
    	Header header = headers.get(HEADER_CONTENT_TYPE);
    	if (header != null)
    	{
    		return header.getValue();
    	}
    	return null;
    }
    public void setContentType(String contentType)
    {
    	headers.put(HEADER_CONTENT_TYPE, new BasicHeader(HEADER_CONTENT_TYPE, contentType));
    }
    
    public HttpEntity getRequestBody()
    {
        return requestBody;
    }
    public void setRequestBody(String body)
    {
        requestBody = new StringEntity(body, ContentType.create(getContentType(), "UTF-8"));

    }
    public void setRequestBody(byte[] body)
    {
        requestBody = new ByteArrayEntity(body);
    }
    public void setRequestBody(InputStream body)
    {
        requestBody = new InputStreamEntity(body);
    }
    public void setRequestBody(HttpEntity body)
    {
        requestBody = body;
    }
    
    public Header[] getRequestHeaders()
    {
    	return headers.keySet().toArray(new Header[headers.size()]);
    }
    public void addRequestHeader(Header header)
    {
        addRequestHeaders(new Header[] {header});
    }
    public void addRequestHeader(String name, String value)
    {
        addRequestHeader(new BasicHeader(name,value));
    }
    public void addRequestHeaders(Header[] headers)
    {
    	for (Header newHdr : headers) {
    		this.headers.put(newHdr.getName(), newHdr);
    	}
    }
    
    /**
     * An HttpClient Method implementation for the method "TESTING",
     *  which we use in certain unit tests
     */
    private static class TestingMethod extends HttpGet
    {
        private static final String METHOD_NAME = "TESTING";
        
        private TestingMethod(String url)
        {
            super(url);
        }
        
        @Override
		public String getMethod()
        {
            return METHOD_NAME;
		}

    }
}
