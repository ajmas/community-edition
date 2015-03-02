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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AlgorithmParameters;

import org.alfresco.encryption.AlfrescoKeyStore;
import org.alfresco.encryption.AlfrescoKeyStoreImpl;
import org.alfresco.encryption.EncryptionUtils;
import org.alfresco.encryption.Encryptor;
import org.alfresco.encryption.KeyProvider;
import org.alfresco.encryption.KeyResourceLoader;
import org.alfresco.encryption.KeyStoreParameters;
import org.alfresco.encryption.ssl.AuthSSLProtocolSocketFactory;
import org.alfresco.encryption.ssl.SSLEncryptionParameters;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.util.Pair;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.ProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;

/**
 * A factory to create HttpClients and AlfrescoHttpClients based on the setting of the 'secureCommsType' property.
 * 
 * @since 4.0
 */
public class HttpClientFactory
{
    public static enum SecureCommsType
    {
        HTTPS, NONE;
        
        public static SecureCommsType getType(String type)
        {
            if(type.equalsIgnoreCase("https"))
            {
                return HTTPS;
            }
            else if(type.equalsIgnoreCase("none"))
            {
                return NONE;
            }
            else
            {
                throw new IllegalArgumentException("Invalid communications type");
            }
        }
    };

    private SSLEncryptionParameters sslEncryptionParameters;
    private KeyResourceLoader keyResourceLoader;
    private SecureCommsType secureCommsType;

    // for md5 http client (no longer used but kept for now)
    private KeyStoreParameters keyStoreParameters;
    private MD5EncryptionParameters encryptionParameters;

//    private String host;
//    private int port;
//    private int sslPort;
    
    private AlfrescoKeyStore sslKeyStore;
    private AlfrescoKeyStore sslTrustStore;
    private LayeredConnectionSocketFactory sslSocketFactory;

    private int maxTotalConnections = 40;

    private int maxHostConnections = 40;
    
    private int socketTimeout = 0;

    private int connectionTimeout = 0;
    
    public HttpClientFactory()
    {
    }

    public HttpClientFactory(SecureCommsType secureCommsType, SSLEncryptionParameters sslEncryptionParameters,
            KeyResourceLoader keyResourceLoader, KeyStoreParameters keyStoreParameters,
            MD5EncryptionParameters encryptionParameters, String host, int port, int sslPort, int maxTotalConnections,
            int maxHostConnections, int socketTimeout)
    {
        this.secureCommsType = secureCommsType;
        this.sslEncryptionParameters = sslEncryptionParameters;
        this.keyResourceLoader = keyResourceLoader;
        this.keyStoreParameters = keyStoreParameters;
        this.encryptionParameters = encryptionParameters;
        this.maxTotalConnections = maxTotalConnections;
        this.maxHostConnections = maxHostConnections;
        this.socketTimeout = socketTimeout;
        init();
    }

    public void init()
    {
        this.sslKeyStore = new AlfrescoKeyStoreImpl(sslEncryptionParameters.getKeyStoreParameters(),  keyResourceLoader);
        this.sslTrustStore = new AlfrescoKeyStoreImpl(sslEncryptionParameters.getTrustStoreParameters(), keyResourceLoader);
        this.sslSocketFactory = new AuthSSLProtocolSocketFactory(sslKeyStore, sslTrustStore, keyResourceLoader);       
    }

    public boolean isSSL()
    {
        return secureCommsType == SecureCommsType.HTTPS;
    }

    public void setSecureCommsType(String type)
    {
        try
        {
            this.secureCommsType = SecureCommsType.getType(type);
        }
        catch(IllegalArgumentException e)
        {
            throw new AlfrescoRuntimeException("", e);
        }
    }
    
    public void setSSLEncryptionParameters(SSLEncryptionParameters sslEncryptionParameters)
    {
        this.sslEncryptionParameters = sslEncryptionParameters;
    }

    public void setKeyStoreParameters(KeyStoreParameters keyStoreParameters)
    {
        this.keyStoreParameters = keyStoreParameters;
    }

    public void setEncryptionParameters(MD5EncryptionParameters encryptionParameters)
    {
        this.encryptionParameters = encryptionParameters;
    }

    public void setKeyResourceLoader(KeyResourceLoader keyResourceLoader)
    {
        this.keyResourceLoader = keyResourceLoader;
    }
    
    /**
     * @return the maxTotalConnections
     */
    public int getMaxTotalConnections()
    {
        return maxTotalConnections;
    }

    /**
     * @param maxTotalConnections the maxTotalConnections to set
     */
    public void setMaxTotalConnections(int maxTotalConnections)
    {
        this.maxTotalConnections = maxTotalConnections;
    }

    /**
     * @return the maxHostConnections
     */
    public int getMaxHostConnections()
    {
        return maxHostConnections;
    }

    /**
     * @param maxHostConnections the maxHostConnections to set
     */
    public void setMaxHostConnections(int maxHostConnections)
    {
        this.maxHostConnections = maxHostConnections;
    }

    /**
     * Attempts to connect to a server will timeout after this period (millis).
     * Default is zero (the timeout is not used).
     * 
     * @param connectionTimeout time in millis.
     */
    public void setConnectionTimeout(int connectionTimeout)
    {
        this.connectionTimeout = connectionTimeout;
    }

    protected HttpClientBuilder getBaseHttpClientBuilder()
    {
    	RequestConfig requestConfig = RequestConfig.custom()
    		    .setSocketTimeout(socketTimeout)
    		    .setConnectTimeout(connectionTimeout)
    		    .setStaleConnectionCheckEnabled(true)
    		    .setRedirectsEnabled(true)
    		    .build();
    	
    	SocketConfig socketConfig = SocketConfig.custom()
    			.setTcpNoDelay(true)
    			.build();
    	
    	return HttpClientBuilder.create()
    			.setRedirectStrategy(new LaxRedirectStrategy())
    			.setMaxConnTotal(maxTotalConnections)
    			.setMaxConnPerRoute(maxHostConnections)
    			.setDefaultRequestConfig(requestConfig)
    			.setDefaultSocketConfig(socketConfig);    	    			
    }
    
    protected HttpClientBuilder getBaseHttpsClientBuilder()
    {
    	return getBaseHttpClientBuilder()
    			.setSSLSocketFactory(sslSocketFactory);
    }
    
    protected HttpClient constructHttpClient()
    {    	
    	return getBaseHttpClientBuilder().build();       
    }
    

    protected CloseableHttpClient getHttpsClient()
    {
    	
    	HttpClientBuilder httpClientBuilder = getBaseHttpClientBuilder();
    	
    	httpClientBuilder.setSSLSocketFactory(sslSocketFactory);
    	
    	return httpClientBuilder.build();    	
    }

    protected CloseableHttpClient getDefaultHttpClient()
    {
        return getBaseHttpClientBuilder().build();
    }
    
    protected AlfrescoHttpClient getAlfrescoHttpsClient()
    {
        AlfrescoHttpClient repoClient = new HttpsClient(getHttpsClient());
        return repoClient;
    }

    protected AlfrescoHttpClient getAlfrescoHttpClient()
    {
        AlfrescoHttpClient repoClient = new DefaultHttpClient(getDefaultHttpClient());
        return repoClient;
    }
    
    protected HttpClient getMD5HttpClient(String host, int port)
    {
        HttpClient httpClient = constructHttpClient();
        return httpClient;
    }
    
    protected AlfrescoHttpClient getAlfrescoMD5HttpClient(String host, int port)
    {
        AlfrescoHttpClient repoClient = new SecureHttpClient(getDefaultHttpClient(), keyResourceLoader, host, port,
                keyStoreParameters, encryptionParameters);
        return repoClient;
    }
    
    /**
     * For testing.
     * 
     * @param host
     * @param port
     * @param encryptionService
     * @return
     */
    protected AlfrescoHttpClient getAlfrescoMD5HttpClient(String host, int port, EncryptionService encryptionService)
    {
        AlfrescoHttpClient repoClient = new SecureHttpClient(getDefaultHttpClient(), encryptionService);
        return repoClient;
    }
    
    public AlfrescoHttpClient getRepoClient(String host, int port)
    {
        AlfrescoHttpClient repoClient = null;

        if(secureCommsType == SecureCommsType.HTTPS)
        {
            repoClient = getAlfrescoHttpsClient();
        }
        else if(secureCommsType == SecureCommsType.NONE)
        {
            repoClient = getAlfrescoHttpClient();
        }
        else
        {
            throw new AlfrescoRuntimeException("Invalid Solr secure communications type configured in alfresco.secureComms, should be 'ssl'or 'none'");
        }

        return repoClient;
    }
    
    public CloseableHttpClient getHttpClient()
    {
    	CloseableHttpClient httpClient = null;

        if(secureCommsType == SecureCommsType.HTTPS)
        {
            httpClient = getHttpsClient();
        }
        else if(secureCommsType == SecureCommsType.NONE)
        {
            httpClient = getDefaultHttpClient();
        }
        else
        {
            throw new AlfrescoRuntimeException("Invalid Solr secure communications type configured in alfresco.secureComms, should be 'ssl'or 'none'");
        }

        return httpClient;
    }
    
    public HttpClientBuilder getHttpClientBuilder()
    {
        HttpClientBuilder httpClientBuilder = null;

        if(secureCommsType == SecureCommsType.HTTPS)
        {
        	httpClientBuilder = getBaseHttpsClientBuilder();
        }
        else if(secureCommsType == SecureCommsType.NONE)
        {
        	httpClientBuilder = getBaseHttpClientBuilder();
        }
        else
        {
            throw new AlfrescoRuntimeException("Invalid Solr secure communications type configured in alfresco.secureComms, should be 'ssl'or 'none'");
        }

        return httpClientBuilder;
    }

    
    /**
     * A secure client connection to the repository.
     * 
     * @since 4.0
     *
     */
    class HttpsClient extends AbstractHttpClient
    {
        public HttpsClient(HttpClient httpClient)
        {
            super(httpClient);
        }

        /**
         * Send Request to the repository
         */
        public Response sendRequest(Request req) throws AuthenticationException, ProtocolException, IOException
        {
        	HttpResponse method = super.sendRemoteRequest(req);
            return new HttpMethodResponse(method);
        }
    }
    
    /**
     * Simple HTTP client to connect to the Alfresco server. Simply wraps a HttpClient.
     * 
     * @since 4.0
     */
    class DefaultHttpClient extends AbstractHttpClient
    {        
        public DefaultHttpClient(HttpClient httpClient)
        {
            super(httpClient);
        }

        /**
         * Send Request to the repository
         */
        public Response sendRequest(Request req) throws AuthenticationException, ProtocolException, IOException
        {
            HttpResponse method = super.sendRemoteRequest(req);
            return new HttpMethodResponse(method);
        }
    }
    
    /**
     * Simple HTTP client to connect to the Alfresco server.
     * 
     * @since 4.0
     */
    class SecureHttpClient extends AbstractHttpClient
    {
        private Encryptor encryptor;
        private EncryptionUtils encryptionUtils;
        private EncryptionService encryptionService;
        
        /**
         * For testing purposes.
         * 
         * @param solrResourceLoader
         * @param alfrescoHost
         * @param alfrescoPort
         * @param encryptionParameters
         */
        public SecureHttpClient(HttpClient httpClient, EncryptionService encryptionService)
        {
            super(httpClient);
            this.encryptionUtils = encryptionService.getEncryptionUtils();
            this.encryptor = encryptionService.getEncryptor();
            this.encryptionService = encryptionService;
        }
        
        public SecureHttpClient(HttpClient httpClient, KeyResourceLoader keyResourceLoader, String host, int port,
                KeyStoreParameters keyStoreParameters, MD5EncryptionParameters encryptionParameters)
        {
            super(httpClient);
            this.encryptionService = new EncryptionService(host, port, keyResourceLoader, keyStoreParameters, encryptionParameters);
            this.encryptionUtils = encryptionService.getEncryptionUtils();
            this.encryptor = encryptionService.getEncryptor();
        }
        
        protected HttpUriRequest createMethod(Request req) throws IOException
        {
            byte[] message = null;
            HttpUriRequest method = super.createMethod(req);

            if(req.getMethod().equalsIgnoreCase("POST"))
            {
                message = req.getBody();
                // encrypt body
                Pair<byte[], AlgorithmParameters> encrypted = encryptor.encrypt(KeyProvider.ALIAS_SOLR, null, message);
                encryptionUtils.setRequestAlgorithmParameters(method, encrypted.getSecond());
                
            	RequestConfig requestConfig = RequestConfig.custom()
            			.setExpectContinueEnabled(true)
            			.build();
            	
            	((HttpPost)method).setConfig(requestConfig);
            	
                ByteArrayEntity requestEntity = new ByteArrayEntity(encrypted.getFirst(), ContentType.create("application/octet-stream"));
                ((HttpPost)method).setEntity(requestEntity);
            }

            encryptionUtils.setRequestAuthentication(method, message);

            return method;
        }
        
        protected HttpResponse sendRemoteRequest(Request req) throws AuthenticationException, ProtocolException, IOException
        {
        	HttpResponse method = super.sendRemoteRequest(req);

            // check that the request returned with an ok status
            if(method.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED)
            {
                throw new AuthenticationException(method);
            }
            
            return method;
        }

        /**
         * Send Request to the repository
         */
        public Response sendRequest(Request req) throws AuthenticationException, ProtocolException, IOException
        {
			try {
				String host = (new URI(req.getFullUri())).getHost();
	        	HttpResponse method = super.sendRemoteRequest(req);
	            return new SecureHttpMethodResponse(method, host, encryptionUtils);
			} catch (URISyntaxException e) {
				throw new IOException("Unable to construct URI to extract host", e);
			}

        }
    }
    
    static class SecureHttpMethodResponse extends HttpMethodResponse
    {
        protected String hostAddress;
        protected EncryptionUtils encryptionUtils;
        // Need to get as a byte array because we need to read the request twice, once for authentication
        // and again by the web service.
        protected byte[] decryptedBody;

        public SecureHttpMethodResponse(HttpResponse method, String hostAddress, 
                EncryptionUtils encryptionUtils) throws AuthenticationException, IOException
        {
            super(method);
            this.hostAddress = hostAddress;
            this.encryptionUtils = encryptionUtils;

            if(method.getStatusLine().getStatusCode() == HttpStatus.SC_OK)
            {
                this.decryptedBody = encryptionUtils.decryptResponseBody(method);
                // authenticate the response
                if(!authenticate())
                {
                    throw new AuthenticationException(method);
                }
            }
        }
        
        protected boolean authenticate() throws IOException
        {
            return encryptionUtils.authenticateResponse(method, hostAddress, decryptedBody);
        }
        
        public InputStream getContentAsStream() throws IOException
        {
            if(decryptedBody != null)
            {
                return new ByteArrayInputStream(decryptedBody);
            }
            else
            {
                return null;
            }
        }
    }

//    private static class HttpHostFactory
//    {
//        private Map<String, Protocol> protocols;
//
//        public HttpHostFactory(Protocol httpsProtocol)
//        {
//            protocols = new HashMap<String, Protocol>(2);
//            protocols.put("https", httpsProtocol);
//        }
// 
//        /** Get a host for the given parameters. This method need not be thread-safe. */
//        public HttpHost getHost(String host, int port, String scheme)
//        {
//            if(scheme == null)
//            {
//                scheme = "http";
//            }
//            Protocol protocol = protocols.get(scheme);
//            if(protocol == null)
//            {
//                protocol = Protocol.getProtocol("http");
//                if(protocol == null)
//                {
//                    throw new IllegalArgumentException("Unrecognised scheme parameter");
//                }
//            }
//
//            return new HttpHost(host, port, protocol);
//        }
//    }
//    
//    private static class HostConfigurationWithHostFactory extends HostConfiguration
//    {
//        private final HttpHostFactory factory;
//
//        public HostConfigurationWithHostFactory(HttpHostFactory factory)
//        {
//            this.factory = factory;
//        }
//
//        public synchronized void setHost(String host, int port, String scheme)
//        {
//            setHost(factory.getHost(host, port, scheme));
//        }
//
//        public synchronized void setHost(String host, int port)
//        {
//            setHost(factory.getHost(host, port, "http"));
//        }
//        
//        @SuppressWarnings("unused")
//        public synchronized void setHost(URI uri)
//        {
//            try {
//                setHost(uri.getHost(), uri.getPort(), uri.getScheme());
//            } catch(URIException e) {
//                throw new IllegalArgumentException(e.toString());
//            }
//        }
//    }
//
//    /**
//     * An extension of the DefaultHttpParamsFactory that uses a RRW lock pattern rather than
//     * full synchronization around the parameter CRUD - to avoid locking on many reads. 
//     * 
//     * @author Kevin Roast
//     */
//    public static class NonBlockingHttpParamsFactory extends DefaultHttpParamsFactory
//    {
//        private volatile HttpParams httpParams;
//        
//        /* (non-Javadoc)
//         * @see org.apache.commons.httpclient.params.DefaultHttpParamsFactory#getDefaultParams()
//         */
//        @Override
//        public HttpParams getDefaultParams()
//        {
//            if (httpParams == null)
//            {
//                synchronized (this)
//                {
//                    if (httpParams == null)
//                    {
//                        httpParams = createParams();
//                    }
//                }
//            }
//            
//            return httpParams;
//        }
//        
//        /**
//         * NOTE: This is a copy of the code in {@link DefaultHttpParamsFactory}
//         *       Unfortunately this is required because although the factory pattern allows the 
//         *       override of the default param creation, it does not allow the class of the actual
//         *       HttpParam implementation to be changed.
//         */
//        @Override
//        protected HttpParams createParams()
//        {
//            HttpClientParams params = new NonBlockingHttpParams(null);
//            
//            params.setParameter(HttpMethodParams.USER_AGENT, "Spring Surf via Apache HttpClient/3.1");
//            params.setVersion(HttpVersion.HTTP_1_1);
//            params.setConnectionManagerClass(SimpleHttpConnectionManager.class);
//            params.setCookiePolicy(CookiePolicy.IGNORE_COOKIES);
//            params.setHttpElementCharset("US-ASCII");
//            params.setContentCharset("ISO-8859-1");
//            params.setParameter(HttpMethodParams.RETRY_HANDLER, new DefaultHttpMethodRetryHandler());
//            
//            List<String> datePatterns = Arrays.asList(
//                    new String[] {
//                            DateUtil.PATTERN_RFC1123,
//                            DateUtil.PATTERN_RFC1036,
//                            DateUtil.PATTERN_ASCTIME,
//                            "EEE, dd-MMM-yyyy HH:mm:ss z",
//                            "EEE, dd-MMM-yyyy HH-mm-ss z",
//                            "EEE, dd MMM yy HH:mm:ss z",
//                            "EEE dd-MMM-yyyy HH:mm:ss z",
//                            "EEE dd MMM yyyy HH:mm:ss z",
//                            "EEE dd-MMM-yyyy HH-mm-ss z",
//                            "EEE dd-MMM-yy HH:mm:ss z",
//                            "EEE dd MMM yy HH:mm:ss z",
//                            "EEE,dd-MMM-yy HH:mm:ss z",
//                            "EEE,dd-MMM-yyyy HH:mm:ss z",
//                            "EEE, dd-MM-yyyy HH:mm:ss z",                
//                    }
//            );
//            params.setParameter(HttpMethodParams.DATE_PATTERNS, datePatterns);
//            
//            String agent = null;
//            try
//            {
//                agent = System.getProperty("httpclient.useragent");
//            }
//            catch (SecurityException ignore)
//            {
//            }
//            if (agent != null)
//            {
//                params.setParameter(HttpMethodParams.USER_AGENT, agent);
//            }
//            
//            String preemptiveDefault = null;
//            try
//            {
//                preemptiveDefault = System.getProperty("httpclient.authentication.preemptive");
//            }
//            catch (SecurityException ignore)
//            {
//            }
//            if (preemptiveDefault != null)
//            {
//                preemptiveDefault = preemptiveDefault.trim().toLowerCase();
//                if (preemptiveDefault.equals("true"))
//                {
//                    params.setParameter(HttpClientParams.PREEMPTIVE_AUTHENTICATION, Boolean.TRUE);
//                }
//                else if (preemptiveDefault.equals("false"))
//                {
//                    params.setParameter(HttpClientParams.PREEMPTIVE_AUTHENTICATION, Boolean.FALSE);
//                }
//            }
//            
//            String defaultCookiePolicy = null;
//            try
//            {
//                defaultCookiePolicy = System.getProperty("apache.commons.httpclient.cookiespec");
//            }
//            catch (SecurityException ignore)
//            {
//            }
//            if (defaultCookiePolicy != null)
//            {
//                if ("COMPATIBILITY".equalsIgnoreCase(defaultCookiePolicy))
//                {
//                    params.setCookiePolicy(CookiePolicy.BROWSER_COMPATIBILITY);
//                }
//                else if ("NETSCAPE_DRAFT".equalsIgnoreCase(defaultCookiePolicy))
//                {
//                    params.setCookiePolicy(CookiePolicy.NETSCAPE);
//                }
//                else if ("RFC2109".equalsIgnoreCase(defaultCookiePolicy))
//                {
//                    params.setCookiePolicy(CookiePolicy.RFC_2109);
//                }
//            }
//            
//            return params;
//        }
//    }
//    
//    /**
//     * @author Kevin Roast
//     */
//    public static class NonBlockingHttpParams extends HttpClientParams
//    {
//        private HashMap<String, Object> parameters = new HashMap<String, Object>(8);
//        private ReadWriteLock paramLock = new ReentrantReadWriteLock();
//        
//        public NonBlockingHttpParams()
//        {
//            super();
//        }
//        
//        public NonBlockingHttpParams(HttpParams defaults)
//        {
//            super(defaults);
//        }
//        
//        @Override
//        public Object getParameter(final String name)
//        {
//            // See if the parameter has been explicitly defined
//            Object param = null;
//            paramLock.readLock().lock();
//            try
//            {
//                param = this.parameters.get(name);
//            }
//            finally
//            {
//                paramLock.readLock().unlock();
//            }
//            if (param == null)
//            {
//                // If not, see if defaults are available
//                HttpParams defaults = getDefaults();
//                if (defaults != null)
//                {
//                    // Return default parameter value
//                    param = defaults.getParameter(name);
//                }
//            }
//            return param;
//        }
//        
//        @Override
//        public void setParameter(final String name, final Object value)
//        {
//            paramLock.writeLock().lock();
//            try
//            {
//                this.parameters.put(name, value);
//            }
//            finally
//            {
//                paramLock.writeLock().unlock();
//            }
//        }
//        
//        @Override
//        public boolean isParameterSetLocally(final String name)
//        {
//            paramLock.readLock().lock();
//            try
//            {
//                return (this.parameters.get(name) != null);
//            }
//            finally
//            {
//                paramLock.readLock().unlock();
//            }
//        }
//        
//        @Override
//        public void clear()
//        {
//            paramLock.writeLock().lock();
//            try
//            {
//                this.parameters.clear();
//            }
//            finally
//            {
//                paramLock.writeLock().unlock();
//            }
//        }
//        
//        @Override
//        public Object clone() throws CloneNotSupportedException
//        {
//            NonBlockingHttpParams clone = (NonBlockingHttpParams)super.clone();
//            paramLock.readLock().lock();
//            try
//            {
//                clone.parameters = (HashMap) this.parameters.clone();
//            }
//            finally
//            {
//                paramLock.readLock().unlock();
//            }
//            clone.setDefaults(getDefaults());
//            return clone;
//        }
//    }
}
