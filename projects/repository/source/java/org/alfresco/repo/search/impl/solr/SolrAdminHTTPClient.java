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
package org.alfresco.repo.search.impl.solr;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.servlet.http.HttpServletResponse;

import org.alfresco.httpclient.HttpClientFactory;
import org.alfresco.repo.search.impl.lucene.LuceneQueryParserException;
import org.alfresco.util.ParameterCheck;
import org.apache.commons.codec.net.URLCodec;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/**
 * @author Andy
 */
public class SolrAdminHTTPClient
{
    static Log s_logger = LogFactory.getLog(SolrAdminHTTPClient.class);

    private String adminUrl;
    
    private String baseUrl;

    private HttpClient httpClient;
	private HttpClientFactory httpClientFactory;
	
    public SolrAdminHTTPClient()
    {
    }

    
    public void setBaseUrl(String baseUrl)
    {
        this.baseUrl = baseUrl;
    }

    public void init()
    {
        ParameterCheck.mandatory("baseUrl", baseUrl);
        
    	StringBuilder sb = new StringBuilder();
    	sb.append(baseUrl + "/admin/cores");
    	this.adminUrl = sb.toString();

    	HttpClientBuilder httpClientBuilder = httpClientFactory.getHttpClientBuilder();
    	
    	CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
    	credentialsProvider.setCredentials(new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT), new UsernamePasswordCredentials("admin", "admin"));
    	httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
    	
    	httpClient = httpClientBuilder.build();    	
    }

    public void setHttpClientFactory(HttpClientFactory httpClientFactory)
	{
		this.httpClientFactory = httpClientFactory;
	}

    public JSONObject execute(HashMap<String, String> args)
    {
        return execute(adminUrl, args);
    }

    public JSONObject execute(String relativeHandlerPath, HashMap<String, String> args)
    {
        ParameterCheck.mandatory("relativeHandlerPath", relativeHandlerPath);
        ParameterCheck.mandatory("args", args);

        String path = getPath(relativeHandlerPath);
        try
        {
            URLCodec encoder = new URLCodec();
            StringBuilder url = new StringBuilder();

            for (String key : args.keySet())
            {
                String value = args.get(key);
                if (url.length() == 0)
                {
                    url.append(path);
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

            // PostMethod post = new PostMethod(url.toString());
            HttpGet get = new HttpGet(url.toString());

            try
            {
                HttpResponse response = httpClient.execute(get);

                // Note: redirection is now handled by HttpClient               

                if (response.getStatusLine().getStatusCode() != HttpServletResponse.SC_OK)
                {
                    throw new LuceneQueryParserException("Request failed " + response.getStatusLine().getStatusCode() + " " + url.toString());
                }

                HttpEntity entity = response.getEntity();
                Reader reader = new BufferedReader(new InputStreamReader(entity.getContent()));
                // TODO - replace with streaming-based solution e.g. SimpleJSON ContentHandler
                JSONObject json = new JSONObject(new JSONTokener(reader));                
                EntityUtils.consumeQuietly(entity);
                return json;
            }
            finally
            {
                get.releaseConnection();
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

    private String getPath(String path)
    {
        if (path.startsWith(baseUrl))
        {
            return path;
        }
        else if (path.startsWith("/"))
        {
            return baseUrl + path;
        }
        else
        {
            return baseUrl + '/' + path;
        }
    }

}
