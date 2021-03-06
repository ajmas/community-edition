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
package org.alfresco.solr.query;

import java.io.IOException;

import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.Weight;

/**
 * Base class for queries relating to a set of authorities, e.g. reader set query.
 */
public abstract class AbstractAuthoritySetQuery extends Query
{
    protected String authorities;
    
    /**
     * Construct with authorities.
     * 
     * @param authorities
     */
    public AbstractAuthoritySetQuery(String authorities)
    {
        super();
        this.authorities = authorities;
    }

    /**
     * Subclasses should implement a descriptive toString method.
     */
    @Override
    public abstract String toString();
    
    @Override
    public abstract Weight createWeight(IndexSearcher searcher) throws IOException;
    
    @Override
    public String toString(String field)
    {
        return toString();
    }
    
    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        AbstractAuthoritySetQuery other = (AbstractAuthoritySetQuery) obj;
        if (authorities == null)
        {
            if (other.authorities != null)
                return false;
        }
        else if (!authorities.equals(other.authorities))
            return false;
        return true;
    }
}
