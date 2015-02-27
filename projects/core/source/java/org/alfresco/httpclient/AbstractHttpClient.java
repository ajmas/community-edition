/*
 * Copyright (C) 2005-2014 Alfresco Software Limited.
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
package org.alfresco.httpclient;

import java.io.IOException;
import java.util.Map;

import org.alfresco.error.AlfrescoRuntimeException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.*;
import org.apache.http.client.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;

public abstract class AbstractHttpClient implements AlfrescoHttpClient
{
    private static final Log logger = LogFactory.getLog(AlfrescoHttpClient.class);
    
    public static final String ALFRESCO_DEFAULT_BASE_URL = "/alfresco";
    
    public static final int DEFAULT_SAVEPOST_BUFFER = 4096;
    
    // Remote Server access
    protected HttpClient httpClient = null;
    
    private String baseUrl = ALFRESCO_DEFAULT_BASE_URL;

    public AbstractHttpClient(HttpClient httpClient)
    {
        this.httpClient = httpClient;
    }
    
    public AbstractHttpClient(HttpClientBuilder httpClientBuilder)
    {
    	httpClientBuilder.setRedirectStrategy(new LaxRedirectStrategy());
        this.httpClient = httpClientBuilder.build();
    }
    
    protected HttpClient getHttpClient()
    {
        return httpClient;
    }
    
    /**
     * @return the baseUrl
     */
    public String getBaseUrl()
    {
        return baseUrl;
    }

    /**
     * @param baseUrl the baseUrl to set
     */
    public void setBaseUrl(String baseUrl)
    {
        this.baseUrl = baseUrl;
    }
    
    /**
     * Send Request to the repository
     */
    protected HttpResponse sendRemoteRequest(Request req) throws AuthenticationException, ProtocolException, IOException
    {
        if (logger.isDebugEnabled())
        {
            logger.debug("");
            logger.debug("* Request: " + req.getMethod() + " " + req.getFullUri() + (req.getBody() == null ? "" : "\n" + new String(req.getBody(), "UTF-8")));
        }

        HttpUriRequest method = createMethod(req);

        // execute method
        return executeMethod(method);
    }
    
    protected HttpResponse executeMethod(HttpUriRequest method) throws ProtocolException, IOException
    {
        // execute method

        // TODO: Pool, and sent host configuration and state on execution
        return getHttpClient().execute(method);

    }

    protected HttpUriRequest createMethod(Request req) throws IOException
    {
        StringBuilder url = new StringBuilder(128);
        url.append(baseUrl);
        url.append("/service/");
        url.append(req.getFullUri());

        // construct method
        HttpUriRequest httpMethod = null;
        String method = req.getMethod();
        if(method.equalsIgnoreCase("GET"))
        {
            HttpGet get = new HttpGet(url.toString());
            httpMethod = get;
        }
        else if(method.equalsIgnoreCase("POST"))
        {
            HttpPost post = new HttpPost(url.toString());
            httpMethod = post;
            ByteArrayEntity httpEntity = new ByteArrayEntity(req.getBody(), ContentType.create(req.getType()));
            if (req.getBody().length > DEFAULT_SAVEPOST_BUFFER)
            {
            	RequestConfig requestConfig = RequestConfig.custom()
            			.setExpectContinueEnabled(true)
            			.build();
            	
            	post.setConfig(requestConfig);
            }
            post.setEntity(httpEntity);
            // Note: not able to automatically follow redirects for POST, this is handled by sendRemoteRequest
        }
        else if(method.equalsIgnoreCase("HEAD"))
        {
            HttpHead head = new HttpHead(url.toString());
            httpMethod = head;
        }
        else
        {
            throw new AlfrescoRuntimeException("Http Method " + method + " not supported");
        }

        if (req.getHeaders() != null)
        {
            for (Map.Entry<String, String> header : req.getHeaders().entrySet())
            {
                httpMethod.setHeader(header.getKey(), header.getValue());
            }
        }
        
        return httpMethod;
    }

    /* (non-Javadoc)
     * @see org.alfresco.httpclient.AlfrescoHttpClient#close()
     */
    @Override
    public void close()
    {
       if(httpClient != null && httpClient instanceof CloseableHttpClient)
       {
           try {
			((CloseableHttpClient)httpClient).close();
		} catch (IOException e) {
			// ignore for now
		}
//           HttpConnectionManager connectionManager = httpClient.getHttpConnectionManager();
//           if(connectionManager instanceof MultiThreadedHttpConnectionManager)
//           {
//               ((MultiThreadedHttpConnectionManager)connectionManager).shutdown();
//           }
       }
        
    }
    
    

}
