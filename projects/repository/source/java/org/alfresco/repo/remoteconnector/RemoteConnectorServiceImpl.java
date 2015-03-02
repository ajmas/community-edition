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
package org.alfresco.repo.remoteconnector;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.StringTokenizer;

import org.alfresco.repo.content.MimetypeMap;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.service.cmr.remoteconnector.RemoteConnectorClientException;
import org.alfresco.service.cmr.remoteconnector.RemoteConnectorRequest;
import org.alfresco.service.cmr.remoteconnector.RemoteConnectorResponse;
import org.alfresco.service.cmr.remoteconnector.RemoteConnectorServerException;
import org.alfresco.service.cmr.remoteconnector.RemoteConnectorService;
import org.alfresco.util.HttpClientHelper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.extensions.webscripts.Status;

/**
 * HttpClient powered implementation of {@link RemoteConnectorService}, which 
 *  performs requests to remote HTTP servers.
 *  
 * Note - this class assumes direct connectivity is available to the destination
 *  system, and does not support proxies.
 *  
 * @author Nick Burch
 * @since 4.0.2
 */
public class RemoteConnectorServiceImpl implements RemoteConnectorService
{
    /**
     * The logger
     */
    private static Log logger = LogFactory.getLog(RemoteConnectorServiceImpl.class);
    private static final long MAX_BUFFER_RESPONSE_SIZE = 10*1024*1024;
 
    private static HttpHost httpProxyHost;
    private static HttpHost httpsProxyHost;
    private static Credentials httpProxyCredentials;
    private static Credentials httpsProxyCredentials;
    private static AuthScope httpAuthScope;
    private static AuthScope httpsAuthScope;
            
    /**
     * Initialise the HTTP Proxy Hosts and Params Factory
     */
    static
    {
        // Create an HTTP Proxy Host if appropriate system property set
        httpProxyHost = createProxyHost("http.proxyHost", "http.proxyPort", 80);
        httpProxyCredentials = createProxyCredentials("http.proxyUser", "http.proxyPassword");
        httpAuthScope = createProxyAuthScope(httpProxyHost);
        
        // Create an HTTPS Proxy Host if appropriate system property set
        httpsProxyHost = createProxyHost("https.proxyHost", "https.proxyPort", 443);
        httpsProxyCredentials = createProxyCredentials("https.proxyUser", "https.proxyPassword");
        httpsAuthScope = createProxyAuthScope(httpsProxyHost);
        
        
    }
    
    public RemoteConnectorServiceImpl()
    {}
    
    /**
     * Builds a new Request object
     */
    public RemoteConnectorRequest buildRequest(String url, String method)
    {
        return new RemoteConnectorRequestImpl(url, method);
    }

    /**
     * Builds a new Request object, using HttpClient method descriptions
     */
    public RemoteConnectorRequest buildRequest(String url, Class<? extends HttpRequestBase> method)
    {
        return new RemoteConnectorRequestImpl(url, method);
    }
    
    /**
     * Executes the specified request, and return the response
     */
    public RemoteConnectorResponse executeRequest(RemoteConnectorRequest request) throws IOException, AuthenticationException,
        RemoteConnectorClientException, RemoteConnectorServerException
    {
        RemoteConnectorRequestImpl reqImpl = (RemoteConnectorRequestImpl)request;
        HttpRequestBase httpRequest = reqImpl.getMethodInstance();
        
        // Attach the headers to the request
        for (Header hdr : request.getRequestHeaders())
        {
            httpRequest.addHeader(hdr);
        }
        
        // Attach the body, if possible
        if (httpRequest instanceof  HttpEntityEnclosingRequestBase)
        {
            if (request.getRequestBody() != null)
            {
                ((HttpEntityEnclosingRequestBase)httpRequest).setEntity( reqImpl.getRequestBody() );
            }
        }
        
        // Grab our thread local HttpClient instance
        // Remember - we must then clean it up!        
        CloseableHttpClient httpClient = HttpClientHelper.getHttpClient();
    	HttpClientContext localHttpClientContext = HttpClientContext.create();

        // The url should already be vetted by the RemoteConnectorRequest
        URL url = new URL(request.getURL());
        
        // Use the appropriate Proxy Host if required
        if (httpProxyHost != null && url.getProtocol().equals("http") && requiresProxy(url.getHost()))
        {        	
        	RequestConfig config = RequestConfig.custom()
                    .setProxy(httpProxyHost)                    
                    .build();
        	
        	httpRequest.setConfig(config);

            if (logger.isDebugEnabled())
            {
                logger.debug(" - using HTTP proxy host for: " + url);
            }
            if (httpProxyCredentials != null)
            {
                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(
                		httpAuthScope,
                		httpProxyCredentials);
                
                localHttpClientContext.setCredentialsProvider(credsProvider);

                if (logger.isDebugEnabled())
                {
                    logger.debug(" - using HTTP proxy credentials for proxy: " + httpProxyHost.getHostName());
                }
            }
        }
        else if (httpsProxyHost != null && url.getProtocol().equals("https") && requiresProxy(url.getHost()))
        {            
        	RequestConfig config = RequestConfig.custom()
                    .setProxy(httpsProxyHost)
                    .build();
        	
        	httpRequest.setConfig(config);
        	
        	
            if (logger.isDebugEnabled())
            {
                logger.debug(" - using HTTPS proxy host for: " + url);
            }
            if (httpsProxyCredentials != null)
            {
                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(
                		httpsAuthScope,
                		httpsProxyCredentials);
                
                localHttpClientContext.setCredentialsProvider(credsProvider);
                if (logger.isDebugEnabled())
                {
                    logger.debug(" - using HTTPS proxy credentials for proxy: " + httpsProxyHost.getHostName());
                }
            }
        } 
        
        // Log what we're doing
        if (logger.isDebugEnabled()) {
            logger.debug("Performing " + request.getMethod() + " request to " + request.getURL());
            for (Header hdr : request.getRequestHeaders())
            {
                logger.debug("Header: " + hdr );
            }
            Object requestBody = null;
            if (request != null)
            {
                requestBody = request.getRequestBody();
            }
            if (requestBody != null && requestBody instanceof StringEntity)
            {
            	StringEntity re = (StringEntity)request.getRequestBody();
                logger.debug("Payload (string): " + re.getContent());
            }
            else if (requestBody != null && requestBody instanceof ByteArrayEntity)
            {
                ByteArrayEntity re = (ByteArrayEntity)request.getRequestBody();
                logger.debug("Payload (byte array): " + re.getContent().toString());
            }
            else
            {
                logger.debug("Payload is not of a readable type.");
            }
        }
        
        // Perform the request, and wrap the response
        int status = -1;
        CloseableHttpResponse httpResponse = null;
        String statusText = null;
        RemoteConnectorResponse response = null;
        try
        {
        	httpResponse = httpClient.execute(httpRequest, localHttpClientContext);
            statusText = httpResponse.getStatusLine().getReasonPhrase();
            status = httpResponse.getStatusLine().getStatusCode();
            
            HttpEntity httpEntity = httpResponse.getEntity();

            Header[] responseHdrs = httpResponse.getAllHeaders();
            Header responseContentTypeH = httpEntity.getContentType();
            String responseCharSet = httpEntity.getContentEncoding().getValue();
            String responseContentType = (responseContentTypeH != null ? responseContentTypeH.getValue() : null);
            
            if(logger.isDebugEnabled())
            {
                logger.debug("response url=" + request.getURL() + ", length =" + httpEntity.getContentLength() + ", responceContentType " + responseContentType + ", statusText =" + statusText );
            }
            
            // Decide on how best to handle the response, based on the size
            // Ideally, we want to close the HttpClient resources immediately, but
            //  that isn't possible for very large responses
            // If we can close immediately, it makes cleanup simpler and fool-proof
            if (httpEntity.getContentLength() > MAX_BUFFER_RESPONSE_SIZE || httpEntity.getContentLength() == -1 )
            {
                if(logger.isTraceEnabled())
                {
                	logger.trace("large response (or don't know length) url=" + request.getURL());
                }
                
                // Need to wrap the InputStream in something that'll close
                InputStream wrappedStream = new HttpClientReleasingInputStream(httpRequest, httpResponse);
                httpRequest = null;
                
                // Now build the response
                response = new RemoteConnectorResponseImpl(request, responseContentType, responseCharSet,
                                                           status, responseHdrs, wrappedStream);
            }
            else
            {
                if(logger.isTraceEnabled())
                {
                    logger.debug("small response for url=" + request.getURL());
                }
                // Fairly small response, just keep the bytes and make life simple
                response = new RemoteConnectorResponseImpl(request, responseContentType, responseCharSet,
                                                           status, responseHdrs, httpEntity.getContent());
                
                // Now we have the bytes, we can close the HttpClient resources
                EntityUtils.consumeQuietly(httpEntity);
                httpRequest.releaseConnection();
                httpRequest = null;
            }
        }
        finally
        {
            // Make sure, problems or not, we always tidy up (if not large stream based)
            // This is important because we use a thread local HttpClient instance
            if (httpClient != null)
            {
                httpRequest.releaseConnection();
                httpRequest = null;
            }
        }
        
        
        // Log the response
        if (logger.isDebugEnabled())
        {
            logger.debug("Response was " + status + " " + statusText);
        }
        
        // Decide if we should throw an exception
        if (status >= 300)
        {
            // Specific exceptions
            if (status == Status.STATUS_FORBIDDEN ||
                status == Status.STATUS_UNAUTHORIZED)
            {
            	// TODO Forbidden may need to be handled differently.
            	// TODO Need to get error message into the AuthenticationException
                throw new AuthenticationException(statusText);
            }
            
            // Server side exceptions
            if (status >= 500 && status <= 599)
            {
                logger.error("executeRequest: remote connector server exception: ["+status+"] "+statusText);
                throw new RemoteConnectorServerException(status, statusText);
            }
            if(status == Status.STATUS_PRECONDITION_FAILED)
            {
                logger.error("executeRequest: remote connector client exception: ["+status+"] "+statusText);
                throw new RemoteConnectorClientException(status, statusText, response);
            }
            else
            {
                // Response was too large, report without it
                logger.error("executeRequest: remote connector client exception: ["+status+"] "+statusText);
                throw new RemoteConnectorClientException(status, statusText, null);           
            }
        }
        
        // If we get here, then the request/response was all fine
        // So, return our created response
        return response;
    }
    
    /**
     * Executes the given request, requesting a JSON response, and
     *  returns the parsed JSON received back
     *  
     * @throws ParseException If the response is not valid JSON
     */
    public JSONObject executeJSONRequest(RemoteConnectorRequest request) throws ParseException, IOException, AuthenticationException
    {
        return doExecuteJSONRequest(request, this);
    }
    
    public static JSONObject doExecuteJSONRequest(RemoteConnectorRequest request, RemoteConnectorService service) throws ParseException, IOException, AuthenticationException
    {
        // Set as JSON
        request.setContentType(MimetypeMap.MIMETYPE_JSON);
        
        // Perform the request
        RemoteConnectorResponse response = service.executeRequest(request);
        
        // Parse this as JSON
        JSONParser parser = new JSONParser();
        String jsonText = response.getResponseBodyAsString();
        Object json = parser.parse(jsonText);
        
        // Check it's the right type and return
        if (json instanceof JSONObject)
        {
            return (JSONObject)json;
        }
        else
        {
            throw new ParseException(0, json);
        }
    }
    
    private static class HttpClientReleasingInputStream extends FilterInputStream
    {
        private HttpRequestBase httpRequest;
        private CloseableHttpResponse httpResponse;
        
        private HttpClientReleasingInputStream(HttpRequestBase httpRequest, CloseableHttpResponse httpResponse) throws IOException
        {
            super(httpResponse.getEntity().getContent());
            this.httpRequest = httpRequest;
            this.httpResponse = httpResponse;
        }

        @Override
        public void close() throws IOException
        {
        	EntityUtils.consumeQuietly(httpResponse.getEntity());
            // Tidy the main stream
        	httpResponse.close();
        	
            
            // Now release the underlying resources
            if (httpRequest != null)
            {
                httpRequest.releaseConnection();
                httpRequest = null;
            }
        }

        /**
         * In case the caller has neglected to close the Stream, warn
         *  (as this will break things for other users!) and then close 
         */
        @Override
        protected void finalize() throws Throwable
        {
            if (httpRequest != null)
            {
                logger.warn("RemoteConnector response InputStream wasn't closed but must be! This can cause issues for " +
                		    "other requests in this Thread!");
                
                httpRequest.releaseConnection();
                httpRequest = null;
            }
         
            // Let the InputStream tidy up if it wants to too
            super.finalize();
        }
    }
    
    /**
     * Create proxy host for the given system host and port properties.
     * If the properties are not set, no proxy will be created.
     * 
     * @param hostProperty
     * @param portProperty
     * @param defaultPort
     * 
     * @return ProxyHost if appropriate properties have been set, null otherwise
     */
    private static HttpHost createProxyHost(final String hostProperty, final String portProperty, final int defaultPort)
    {
        final String proxyHost = System.getProperty(hostProperty);
        HttpHost proxy = null;
        if (proxyHost != null && proxyHost.length() != 0)
        {
            final String strProxyPort = System.getProperty(portProperty);
            if (strProxyPort == null || strProxyPort.length() == 0)
            {
                proxy = new HttpHost(proxyHost, defaultPort);
            }
            else
            {
                proxy = new HttpHost(proxyHost, Integer.parseInt(strProxyPort));
            }
            if (logger.isDebugEnabled())
                logger.debug("ProxyHost: " + proxy.toString());
        }
        return proxy;
    }
    
    /**
     * Create the proxy credentials for the given proxy user and password properties.
     * If the properties are not set, not credentials will be created.
     * @param proxyUserProperty
     * @param proxyPasswordProperty
     * @return Credentials if appropriate properties have been set, null otherwise
     */
    private static Credentials createProxyCredentials(final String proxyUserProperty, final String proxyPasswordProperty) 
    {
        final String proxyUser = System.getProperty(proxyUserProperty);
        final String proxyPassword = System.getProperty(proxyPasswordProperty);
        Credentials creds = null;
        if (StringUtils.isNotBlank(proxyUser))
        {
            creds = new UsernamePasswordCredentials(proxyUser, proxyPassword);
        }
        return creds;
    }
    
    /**
     * Create suitable AuthScope for ProxyHost.
     * If the ProxyHost is null, no AuthsScope will be created.
     * @param proxyHost
     * @return Authscope for provided ProxyHost, null otherwise.
     */
    private static AuthScope createProxyAuthScope(final HttpHost proxyHost)
    {
        AuthScope authScope = null;
        if (proxyHost !=  null) 
        {
            authScope = new AuthScope(proxyHost.getHostName(), proxyHost.getPort());
        }
        return authScope;
    }
    
    /**
     * Return true unless the given target host is specified in the <code>http.nonProxyHosts</code> system property.
     * See http://download.oracle.com/javase/1.4.2/docs/guide/net/properties.html
     * @param targetHost    Non-null host name to test
     * @return true if not specified in list, false if it is specifed and therefore should be excluded from proxy
     */
    private boolean requiresProxy(final String targetHost)
    {
        boolean requiresProxy = true;
        final String nonProxyHosts = System.getProperty("http.nonProxyHosts");
        if (nonProxyHosts != null)
        {
            StringTokenizer tokenizer = new StringTokenizer(nonProxyHosts, "|");
            while (tokenizer.hasMoreTokens())
            {
                String pattern = tokenizer.nextToken();
                pattern = pattern.replaceAll("\\.", "\\\\.").replaceAll("\\*", ".*");
                if (targetHost.matches(pattern))
                {
                    requiresProxy = false;
                    break;
                }
            }
        }
        return requiresProxy;
    }
}
