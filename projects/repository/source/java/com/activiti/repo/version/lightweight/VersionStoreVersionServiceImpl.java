package com.activiti.repo.version.lightweight;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.activiti.repo.dictionary.ClassRef;
import com.activiti.repo.dictionary.bootstrap.DictionaryBootstrap;
import com.activiti.repo.policy.PolicyDefinitionService;
import com.activiti.repo.policy.PolicyRuntimeService;
import com.activiti.repo.ref.ChildAssocRef;
import com.activiti.repo.ref.NodeAssocRef;
import com.activiti.repo.ref.NodeRef;
import com.activiti.repo.ref.QName;
import com.activiti.repo.ref.qname.QNamePattern;
import com.activiti.repo.ref.qname.RegexQNamePattern;
import com.activiti.repo.version.ReservedVersionNameException;
import com.activiti.repo.version.Version;
import com.activiti.repo.version.VersionHistory;
import com.activiti.repo.version.VersionLabelPolicy;
import com.activiti.repo.version.VersionService;
import com.activiti.repo.version.VersionServiceException;
import com.activiti.repo.version.common.VersionUtil;
import com.activiti.repo.version.common.counter.VersionCounterDaoService;
import com.activiti.repo.version.policy.OnBeforeCreateVersionPolicy;
import com.activiti.util.AspectMissingException;

/**
 * The light weight version service implementation.
 * 
 * @author Roy Wetheral
 */
public class VersionStoreVersionServiceImpl extends VersionStoreBaseImpl implements VersionService
{
    /**
     * Error messages
     */
    private static final String ERR_NOT_FOUND = "The current version could not be found in the light weight store.";
    private static final String ERR_NO_BRANCHES = "The current implmentation of the light weight version store does " +
                                                    "not support the creation of branches.";
    
    /**
     * The version counter service
     */
    private VersionCounterDaoService versionCounterService = null;
    
    /**
     * The version label policy
     */
    private VersionLabelPolicy versionLabelPolicy = null;
    
    /**
     * Policy definition service
     */
    protected PolicyDefinitionService policyDefinitionService = null;
    
    /**
     * Policy runtime service
     */
    protected PolicyRuntimeService policyRuntimeService = null;
    
    /**
     * Sets the version counter service
     * 
     * @param versionCounterService  the version counter service
     */
    public void setVersionCounterDaoService(VersionCounterDaoService versionCounterService)
    {
        this.versionCounterService = versionCounterService;
    }
    
    /**
     * Sets the version label policy
     * 
     * @param versionLabelPolicy  the version label policy
     */
    public void setVersionLabelPolicy(VersionLabelPolicy versionLabelPolicy)
    {
        this.versionLabelPolicy = versionLabelPolicy;
    }
        
    /**
     * Sets the policy defintion service
     * 
     * @param policyDefintionService  the policy definition service
     */
    public void setPolicyDefinitionService(
            PolicyDefinitionService policyDefinitionService)
    {
        this.policyDefinitionService = policyDefinitionService;
    }
    
    /**
     * Sets the policy runtime service
     * 
     * @param policyRuntimeService  the policy runtime service
     */
    public void setPolicyRuntimeService(
            PolicyRuntimeService policyRuntimeService)
    {
        this.policyRuntimeService = policyRuntimeService;
    }
    
    @Override
    public void initialise()
    {
        super.initialise();
        
        // Register the policies
        this.policyDefinitionService.registerPolicy(this, OnBeforeCreateVersionPolicy.class);
    }
    
    /**
     * @see com.activiti.repo.version.VersionService#createVersion(NodeRef, Map<String, Serializable>)
     */
    public Version createVersion(
            NodeRef nodeRef, 
            Map<String, Serializable> versionProperties)
            throws ReservedVersionNameException, AspectMissingException
    {
        // Get the next version number
        int versionNumber = this.versionCounterService.nextVersionNumber(getVersionStoreReference());
        
        // Create the version
        return createVersion(nodeRef, versionProperties, versionNumber);
    }        

    /**
     * The version's are created from the children upwards with the parent being created first.  This will
     * ensure that the child version references in the version node will point to the version history nodes
     * for the (possibly) newly created version histories.
     * 
     * @see com.activiti.repo.version.VersionService#createVersion(NodeRef, Map<String, Serializable>, boolean)
     */
    public Collection<Version> createVersion(
            NodeRef nodeRef, 
            Map<String, Serializable> versionProperties,
            boolean versionChildren)
            throws ReservedVersionNameException, AspectMissingException
    {
        // Get the next version number
        int versionNumber = this.versionCounterService.nextVersionNumber(getVersionStoreReference());
        
        // Create the versions
        return createVersion(nodeRef, versionProperties, versionChildren, versionNumber);
    }
    
    /**
     * Helper method used to create the version when the versionChildren flag is provided.  This method
     * ensures that all the children (if the falg is set to true) are created with the same version 
     * number, this ensuring that the version stripe is correct.
     * 
     * @param nodeRef                           the parent node reference
     * @param versionProperties                 the version properties
     * @param versionChildren                   indicates whether to version the children of the parent
     *                                          node
     * @param versionNumber                     the version number
     
     * @return                                  a collection of the created versions
     * @throws ReservedVersionNameException     thrown if there is a reserved version property name clash
     * @throws AspectMissingException    thrown if the version aspect is missing from a node
     */
    private Collection<Version> createVersion(
            NodeRef nodeRef, 
            Map<String, Serializable> versionProperties,
            boolean versionChildren,
            int versionNumber) 
            throws ReservedVersionNameException, AspectMissingException
    {

        Collection<Version> result = new ArrayList<Version>();
        
        if (versionChildren == true)
        {
            // Get the children of the node
            Collection<ChildAssocRef> children = this.dbNodeService.getChildAssocs(nodeRef);
            for (ChildAssocRef childAssoc : children)
            {
                // Recurse into this method to version all the children with the same version number
                Collection<Version> childVersions = createVersion(
                        childAssoc.getChildRef(), 
                        versionProperties, 
                        versionChildren, 
                        versionNumber);
                result.addAll(childVersions);
            }
        }
        
        result.add(createVersion(nodeRef, versionProperties, versionNumber));
        
        return result;
    }

    /**
     * Note:  we can't control the order of the list, so if we have children and parents in the list and the
     * parents get versioned before the children and the children are not already versioned then the parents 
     * child references will be pointing to the node ref, rather than the verison history.
     * 
     * @see com.activiti.repo.version.VersionService#createVersion(List<NodeRef>, Map<String, Serializable>)
     */
    public Collection<Version> createVersion(
            Collection<NodeRef> nodeRefs, 
            Map<String, Serializable> versionProperties)
            throws ReservedVersionNameException, AspectMissingException
    {
        Collection<Version> result = new ArrayList<Version>(nodeRefs.size());
        
        // Get the next version number
        int versionNumber = this.versionCounterService.nextVersionNumber(getVersionStoreReference());
        
        // Version each node in the list
        for (NodeRef nodeRef : nodeRefs)
        {
            result.add(createVersion(nodeRef, versionProperties, versionNumber));
        }
        
        return result;
    }
    
    /**
     * Creates a new version of the passed node assigning the version properties 
     * accordingly.
     * 
     * @param  nodeRef              a node reference
     * @param  versionProperties    the version properties
     * @param  versionNumber        the version number
     * @return                      the newly created version
     * @throws ReservedVersionNameException
     *                              thrown if there is a name clash in the version properties  
     * @throws AspectMissingException    
     *                              thrown if the version aspect is missing from the node   
     */
    private Version createVersion(
            NodeRef nodeRef, 
            Map<String, Serializable> versionProperties, 
            int versionNumber)
            throws ReservedVersionNameException, AspectMissingException
    {

        // Check for the version aspect
        checkForVersionAspect(nodeRef);
        
        // Call the onBeforeCreateVersionPolicy 
        OnBeforeCreateVersionPolicy policy = this.policyRuntimeService.getClassBehaviour(
                OnBeforeCreateVersionPolicy.class, 
                this.nodeService,
                nodeRef);
        if (policy != null)
        {
            policy.OnBeforeCreateVersion(nodeRef);
        }
        
        // TODO we need some way of 'locking' the current node to ensure no modifications (or other versions) 
        //      can take place untill the versioning process is complete
        
        // Check that the supplied additional version properties do not clash with the reserved ones
        VersionUtil.checkVersionPropertyNames(versionProperties.keySet());
        
        // Check the repository for the version history for this node
        NodeRef versionHistoryRef = getVersionHistoryNodeRef(nodeRef); 
        NodeRef currentVersionRef = null;
        
        if (versionHistoryRef == null)
        {
            HashMap<QName, Serializable> props = new HashMap<QName, Serializable>();
            props.put(PROP_QNAME_VERSIONED_NODE_ID, nodeRef.getId());
            
            // Create a new version history node
            ChildAssocRef childAssocRef = this.dbNodeService.createNode(
                    this.versionStoreRootNodeRef, 
                    CHILD_QNAME_VERSION_HISTORIES, 
                    CLASS_REF_VERSION_HISTORY,
                    props);
            versionHistoryRef = childAssocRef.getChildRef();            
        }
        else
        {
            // Since we have an exisiting version history we should be able to lookup
            // the current version
            currentVersionRef = getCurrentVersionNodeRef(versionHistoryRef, nodeRef);     
            
            if (currentVersionRef == null)
            {
                throw new VersionServiceException(ERR_NOT_FOUND);
            }
            
            // Need to check that we are not about to create branch since this is not currently supported
            VersionHistory versionHistory = buildVersionHistory(versionHistoryRef, nodeRef);
            Version currentVersion = getVersion(currentVersionRef);
            if (versionHistory.getSuccessors(currentVersion).size() != 0)
            {
                throw new VersionServiceException(ERR_NO_BRANCHES);
            }
        }
        
        // Create the new version node (child of the version history)
        NodeRef newVersionRef = createNewVersion(
                nodeRef, 
                versionHistoryRef,
                currentVersionRef, 
                versionProperties, 
                versionNumber);
        
        // 'Freeze' the current nodes state in the new version node
        freezeNodeState(nodeRef, newVersionRef);
        
        if (currentVersionRef == null)
        {
            // Set the new version to be the root version in the version history
            this.dbNodeService.createAssociation(
                    versionHistoryRef, 
                    newVersionRef, 
                    VersionStoreVersionServiceImpl.ASSOC_ROOT_VERSION);
        }
        else
        {
            // Relate the new version to the current version as its successor
            this.dbNodeService.createAssociation(
                    currentVersionRef, 
                    newVersionRef, 
                    VersionStoreVersionServiceImpl.ASSOC_SUCCESSOR);
        }
        
        // Create the version data object
        Version version = getVersion(newVersionRef);
        
        // Set the new version label on the versioned node
        this.dbNodeService.setProperty(
                nodeRef, 
                VersionService.PROP_QNAME_CURRENT_VERSION_LABEL, 
                version.getVersionLabel());
        
        // Return the data object representing the newly created version
        return version;
    }

    /**
     * @see com.activiti.repo.version.VersionService#getVersionHistory(NodeRef)
     */
    public VersionHistory getVersionHistory(NodeRef nodeRef)
        throws AspectMissingException
    {
        // Check for the version aspect
        checkForVersionAspect(nodeRef);

        // TODO could definatly do with a cache since these are read-only objects ... maybe not 
        //      since they are dependant on the workspace of the node passed
        
        VersionHistory versionHistory = null;
        
        NodeRef versionHistoryRef = getVersionHistoryNodeRef(nodeRef);
        if (versionHistoryRef != null)
        {
            versionHistory = buildVersionHistory(versionHistoryRef, nodeRef);
        }
        
        return versionHistory;
    }           
    
    /**
     * Creates a new version node, setting the properties both calculated and specified.
     * 
     * @param versionableNodeRef  the reference to the node being versioned
     * @param versionHistoryRef   version history node reference
     * @param preceedingNodeRef   the version node preceeding this in the version history
     * 							  , null if none
     * @param versionProperties   version properties
     * @param versionNumber		  the version number
     * @return                    the version node reference
     */
    private NodeRef createNewVersion(
			NodeRef versionableNodeRef, 
			NodeRef versionHistoryRef, 
			NodeRef preceedingNodeRef, 
			Map<String, Serializable> 
			versionProperties, 
			int versionNumber)
    {
        HashMap<QName, Serializable> props = new HashMap<QName, Serializable>(15, 1.0f);
        
        // Set the version number for the new version
        props.put(PROP_QNAME_VERSION_NUMBER, Integer.toString(versionNumber));
        
        // Set the created date
        props.put(PROP_QNAME_VERSION_CREATED_DATE, new Date());
		
		// Set the versionable node id
		props.put(PROP_QNAME_FROZEN_NODE_ID, versionableNodeRef.getId());
		
		// Set the versionable node store protocol
		props.put(PROP_QNAME_FROZEN_NODE_STORE_PROTOCOL, versionableNodeRef.getStoreRef().getProtocol());
		
		// Set the versionable node store id
		props.put(PROP_QNAME_FROZEN_NODE_STORE_ID, versionableNodeRef.getStoreRef().getIdentifier());
        
        // Store the current node type
        ClassRef nodeType = this.nodeService.getType(versionableNodeRef);
        props.put(PROP_QNAME_FROZEN_NODE_TYPE, nodeType);
        
        // Store the current aspects
        Set<ClassRef> aspects = this.nodeService.getAspects(versionableNodeRef);
		props.put(PROP_QNAME_FROZEN_ASPECTS, (Serializable)aspects);
        
        // Calculate the version label
        String versionLabel = null;
        if (this.versionLabelPolicy != null)
        {
            // Use the policy to create the version label
            Version preceedingVersion = getVersion(preceedingNodeRef);
            versionLabel = this.versionLabelPolicy.getVersionLabelValue(preceedingVersion, versionNumber, versionProperties);
        }
        else
        {
            // The default version label policy is to set it equal to the verion number
            versionLabel = Integer.toString(versionNumber);
        }
        props.put(PROP_QNAME_VERSION_LABEL, versionLabel);
        
        // TODO any other calculated properties ...
        
        // Set the property values
        for (String key : versionProperties.keySet())
        {
            // Apply the namespace to the verison property
            QName propertyName = QName.createQName(
                    VersionStoreVersionServiceImpl.NAMESPACE_URI,
                    key);
            
            // Set the property value on the node
            props.put(propertyName, versionProperties.get(key));
        }
        
        // Create the new version
        ChildAssocRef childAssocRef = this.dbNodeService.createNode(
                versionHistoryRef, 
                VersionStoreBaseImpl.CHILD_QNAME_VERSIONS,
                CLASS_REF_VERSION,
                props);
        return childAssocRef.getChildRef();
    }
    
    /**
     * Takes the current state of the node and 'freezes' it on the version node.
     * <p>
     * TODO describe how children are frozen and how this behaviour can be overridden.
     * 
     * @param nodeRef     the node reference
     * @param versionRef  the version node reference
     */
    private void freezeNodeState(NodeRef nodeRef, NodeRef versionRef)
    {
        // Copy the current values of the node onto the version node, thus taking a snap shot of the values
        Map<QName, Serializable> nodeProperties = this.nodeService.getProperties(nodeRef);
        if (nodeProperties != null)
        {
            // Copy the property values from the node onto the version node
            for (QName propertyName : nodeProperties.keySet())
            {                               
                // Get the property values
                HashMap<QName, Serializable> properties = new HashMap<QName, Serializable>();
                properties.put(PROP_QNAME_QNAME, propertyName);
                properties.put(PROP_QNAME_VALUE, nodeProperties.get(propertyName));
                
                // Create the node storing the frozen attribute details
                this.dbNodeService.createNode(
                        versionRef, 
                        CHILD_QNAME_VERSIONED_ATTRIBUTES,
                        CLASS_REF_VERSIONED_PROPERTY,
                        properties);                
            }
        }
        
        // TODO here we need to deal with any content that might be on the node
        
        // TODO the following behaviour is default and should overrideable (ie: can choose when to ignore, version or 
        //      reference children) how do we do this?
        
        // TODO need to check that the node is of type container (at the moment you can't version a non-container
        //      node !!
        
        // Get the children of the versioned node
        Collection<ChildAssocRef> childAssocRefs = this.nodeService.getChildAssocs(nodeRef);
        for (ChildAssocRef childAssocRef : childAssocRefs)
        {
            HashMap<QName, Serializable> properties = new HashMap<QName, Serializable>();
            
            // Set the qname, isPrimary and nthSibling properties
            properties.put(PROP_QNAME_ASSOC_QNAME, childAssocRef.getQName());
            properties.put(PROP_QNAME_IS_PRIMARY, Boolean.valueOf(childAssocRef.isPrimary()));
            properties.put(PROP_QNAME_NTH_SIBLING, Integer.valueOf(childAssocRef.getNthSibling()));
            
            // Need to determine whether the child is versioned or not
            NodeRef versionHistoryRef = getVersionHistoryNodeRef(childAssocRef.getChildRef());
            if (versionHistoryRef == null)
            {
                // Set the reference property to point to the child node
                properties.put(DictionaryBootstrap.PROP_QNAME_REFERENCE, childAssocRef.getChildRef());
            }
            else
            {
                // Set the reference property to point to the version history
                properties.put(DictionaryBootstrap.PROP_QNAME_REFERENCE, versionHistoryRef);
            }
            
            // Create child version reference
            ChildAssocRef newRef = this.dbNodeService.createNode(
                    versionRef,
                    CHILD_QNAME_VERSIONED_CHILD_ASSOCS,
                    CLASS_REF_VERSIONED_CHILD_ASSOC, 
                    properties);
        }
        
        // Version the target assocs
        List<NodeAssocRef> targetAssocs = this.nodeService.getTargetAssocs(nodeRef, RegexQNamePattern.MATCH_ALL);
        for (NodeAssocRef targetAssoc : targetAssocs)
        {
            HashMap<QName, Serializable> properties = new HashMap<QName, Serializable>();
            
            // Set the qname of the association
            properties.put(PROP_QNAME_ASSOC_QNAME, targetAssoc.getQName());
            
            // Need to determine whether the target is versioned or not
            NodeRef versionHistoryRef = getVersionHistoryNodeRef(targetAssoc.getTargetRef());
            if (versionHistoryRef == null)
            {
                // Set the reference property to point to the child node
                properties.put(DictionaryBootstrap.PROP_QNAME_REFERENCE, targetAssoc.getTargetRef());
            }
            else
            {
                // Set the reference property to point to the version history
                properties.put(DictionaryBootstrap.PROP_QNAME_REFERENCE, versionHistoryRef);
            }
            
            // Create child version reference
            ChildAssocRef newRef = this.dbNodeService.createNode(
                    versionRef,
                    CHILD_QNAME_VERSIONED_ASSOCS, 
                    CLASS_REF_VERSIONED_ASSOC, 
                    properties);
        }
    }    
}
