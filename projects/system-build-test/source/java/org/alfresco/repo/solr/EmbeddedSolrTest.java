/*
 * Copyright (C) 2005-2013 Alfresco Software Limited.
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
package org.alfresco.repo.solr;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;

import org.alfresco.encryption.KeyResourceLoader;
import org.alfresco.encryption.KeyStoreParameters;
import org.alfresco.encryption.ssl.SSLEncryptionParameters;
import org.alfresco.httpclient.HttpClientFactory;
import org.alfresco.httpclient.HttpClientFactory.SecureCommsType;
import org.alfresco.repo.search.impl.lucene.LuceneQueryParserException;
import org.apache.commons.codec.net.URLCodec;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/**
 * @author Andy
 *
 */
public class EmbeddedSolrTest  extends TestCase
{
    private String baseUrl;

    private HttpClient httpClient;
    
    @Override
    public void setUp() throws Exception
    {
        KeyStoreParameters keyStoreParameters = new KeyStoreParameters("SSL Key Store", "JCEKS", null, "ssl-keystore-passwords.properties", "ssl.keystore");
        KeyStoreParameters trustStoreParameters = new KeyStoreParameters("SSL Trust Store", "JCEKS", null, "ssl-truststore-passwords.properties", "ssl.truststore");
 
        SSLEncryptionParameters sslEncryptionParameters = new SSLEncryptionParameters(keyStoreParameters, trustStoreParameters);
        
        ClasspathKeyResourceLoader keyResourceLoader = new ClasspathKeyResourceLoader();
        HttpClientFactory httpClientFactory = new HttpClientFactory(SecureCommsType.getType("https"), sslEncryptionParameters, keyResourceLoader, null, null, "localhost", 8080,
                8443, 40, 40, 0);
        
        StringBuilder sb = new StringBuilder();
        sb.append("/solr/admin/cores");
        this.baseUrl = sb.toString();

    	HttpClientBuilder httpClientBuilder = httpClientFactory.getHttpClientBuilder();
    	
		// TODO remove credentials because we're using SSL?
    	CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
    	credentialsProvider.setCredentials(new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT), 
    			new UsernamePasswordCredentials("admin", "admin"));
    	httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);               
     }
    
    
    public void testEmbeddedAFTS() throws JSONException
    {
        HashMap<String, String> args = new HashMap<String, String>();
        args.put("action", "TEST");
        args.put("wt", "json");
        JSONObject json = execute(args);
        Counter errors = new Counter();
        Counter failures = new Counter();
        countErrorsAndFailures(json, errors, failures);
        assertEquals("Errors", 0, errors.value());
        assertEquals("Failures", 0, failures.value());
    }
    
    public void testEmbeddedCmis() throws JSONException
    {
        HashMap<String, String> args = new HashMap<String, String>();
        args.put("action", "CMISTEST");
        args.put("wt", "json");
        JSONObject json = execute(args);
        Counter errors = new Counter();
        Counter failures = new Counter();
        countErrorsAndFailures(json, errors, failures);
        assertEquals("Errors", 0, errors.value());
        assertEquals("Failures", 0, failures.value());
    }
    
    private void countErrorsAndFailures(JSONObject object, Counter errors, Counter failures) throws JSONException
    {
        for(Iterator<?> it = object.keys(); it.hasNext(); /**/)
        {
            String key = (String)it.next();
            Object current = object.get(key);
            if(current instanceof JSONObject)
            {
                countErrorsAndFailures((JSONObject)current, errors, failures);
            }
            else if(current instanceof JSONArray)
            {
                
            }
            else
            {
                String value = object.getString(key);
                if(value.contains("ERROR"))
                {
                    errors.increment();
                }
                if(value.contains("FAILED"))
                {
                    failures.increment();
                }
            }
        }
    }
    
    private class ClasspathKeyResourceLoader implements KeyResourceLoader
    {
        @Override
        public InputStream getKeyStore(String location) throws FileNotFoundException
        {
            return getClass().getClassLoader().getResourceAsStream(location);
        }

        @Override
        public Properties loadKeyMetaData(String location) throws IOException
        {
            Properties p = new Properties();
            p.load(getClass().getClassLoader().getResourceAsStream(location));
            return p;
        }
    }
    
    public JSONObject execute(HashMap<String, String>args)
    {   
        try
        {   
            URLCodec encoder = new URLCodec();
            StringBuilder url = new StringBuilder();
            
            for(String key : args.keySet())
            {
                String value = args.get(key);
                if(url.length() == 0)
                {
                    url.append(baseUrl);
                    url.append("?");
                    url.append(encoder.encode(key, "UTF-8"));
                    url.append("=");
                    url.append(encoder.encode(value, "UTF-8"));
                }
                else
                {
                    url.append("&");
                    url.append(encoder.encode(key, "UTF-8"));
                    url.append("=");
                    url.append(encoder.encode(value, "UTF-8")); 
                }
                
            }
          
            HttpPost post = new HttpPost(url.toString());
            HttpEntity entity = null;
            try
            {
                HttpResponse response = httpClient.execute(post);

                if (response.getStatusLine().getStatusCode() != HttpServletResponse.SC_OK)
                {
                    throw new LuceneQueryParserException("Request failed " + response.getStatusLine().getStatusCode() + " " + url.toString());
                }

                entity = response.getEntity();
                Reader reader = new BufferedReader(new InputStreamReader(entity.getContent()));
                // TODO - replace with streaming-based solution e.g. SimpleJSON ContentHandler
                JSONObject json = new JSONObject(new JSONTokener(reader));
                return json;
            }
            finally
            {
                post.releaseConnection();
                EntityUtils.consumeQuietly(entity);
            }
        }
        catch (UnsupportedEncodingException e)
        {
            throw new LuceneQueryParserException("", e);
        }
        catch (IOException e)
        {
            throw new LuceneQueryParserException("", e);
        }
        catch (JSONException e)
        {
            throw new LuceneQueryParserException("", e);
        }
    }
    
    private static class Counter
    {
        int value = 0;
        
        Counter()
        {
            
        }
        
        void increment()
        {
            value++;
        }
        
        int value()
        {
            return value;
        }
    }
}
