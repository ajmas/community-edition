/*
 * Copyright (C) 2005-2014 Alfresco Software Limited.
 * This file is part of Alfresco
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */

package org.alfresco.share.reports;

import java.util.List;

import org.alfresco.po.share.dashlet.TopSiteContributorDashlet;
import org.alfresco.po.share.enums.Dashlets;
import org.alfresco.po.share.enums.UserRole;
import org.alfresco.po.share.site.SiteDashboardPage;
import org.alfresco.test.FailedTestListener;
import org.alfresco.po.share.util.SiteUtil;
import org.alfresco.share.util.AbstractUtils;
import org.alfresco.share.util.ShareUser;
import org.alfresco.share.util.ShareUserDashboard;
import org.alfresco.share.util.ShareUserMembers;
import org.alfresco.share.util.api.CreateUserAPI;
import org.alfresco.webdrone.RenderTime;
import org.apache.log4j.Logger;
import org.openqa.selenium.NoSuchElementException;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;



/**
 * 
 * Top site contributor report dashlet tests
 * 
 * @author jcule
 *
 */

@Listeners(FailedTestListener.class)
public class TopSiteContributorReportTest extends AbstractUtils
{
    private static final Logger logger = Logger.getLogger(TopSiteContributorReportTest.class);

    private static String testPassword = DEFAULT_PASSWORD;
    protected String testUser;
    protected String siteName = "";
    
    private static int firstNumberOfFiles = 7;
    private static int secondNumberOfFiles = 4;
    private static int thirdNumberOfFiles = 1;
    private static int fourthNumberOfFiles = 6;
    private static int fifthNumberOfFiles = 10;


    @Override
    @BeforeClass(alwaysRun = true)
    public void setup() throws Exception
    {
        super.setup();
        testName = this.getClass().getSimpleName();
        testUser = testName + "@" + DOMAIN_FREE;
        logger.info("Starting Tests: " + testName);
    }

    /**
     * 1) Create test user
     * 2) Login as test user
     * 3) Create site
     * 4) Create user1
     * 5) Add user1 with write permissions to write to the site
     * 6) Test user logs out
     * 7) User1 logs in
     * 8) User1 creates txt files
     * 9) User1 logs out
     * 10) Steps 2,4,5,6,7,8,9 repeated for user2, user3, user4 and user5
     * 
     * @throws Exception
     */
    @Test(groups = { "DataPrepTopSiteContributorReport" })
    public void dataPrep_TopSiteContributor_AONE_16001() throws Exception
    {
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String[] testUserInfo = new String[] { testUser };
        String siteName = getSiteName(testName);

        // Create test user
        CreateUserAPI.createActivateUserAsTenantAdmin(drone, ADMIN_USERNAME, testUserInfo);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // test user creates site
        SiteUtil.createSite(drone, siteName, AbstractUtils.SITE_VISIBILITY_PRIVATE);

        // first user
        String testUser1 = getUserNameForDomain(testName + "-0", DOMAIN_FREE);
        String[] testUserInfo1 = new String[] { testUser1 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo1);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);
        
        // add user with write permissions to write to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser1, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser1, DEFAULT_PASSWORD);

        // first user creates files
        createUsersAndUploadFiles(firstNumberOfFiles, siteName);

        // first user logs out
        ShareUser.logout(drone);

        // second user
        String testUser2 = getUserNameForDomain(testName + "-2", DOMAIN_FREE);
        String[] testUserInfo2 = new String[] { testUser2 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo2);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // add user with write permissions to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser2, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser2, DEFAULT_PASSWORD);

        // second user creates files
        createUsersAndUploadFiles(secondNumberOfFiles, siteName);

        // second user logs out
        ShareUser.logout(drone);

        // third user
        String testUser3 = getUserNameForDomain(testName + "-3", DOMAIN_FREE);
        String[] testUserInfo3 = new String[] { testUser3 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo3);

        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);
        
        // add user with write permissions to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser3, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser3, DEFAULT_PASSWORD);

        // first user creates files
        createUsersAndUploadFiles(thirdNumberOfFiles, siteName);

        // third user logs out
        ShareUser.logout(drone);

        // fourth user
        String testUser4 = getUserNameForDomain(testName + "-4", DOMAIN_FREE);
        String[] testUserInfo4 = new String[] { testUser4 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo4);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // add user with write permissions to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser4, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser4, DEFAULT_PASSWORD);

        // fourth user creates files
        createUsersAndUploadFiles(fourthNumberOfFiles, siteName);

        // fourth user logs out
        ShareUser.logout(drone);

        // fifth user
        String testUser5 = getUserNameForDomain(testName + "-5", DOMAIN_FREE);
        String[] testUserInfo5 = new String[] { testUser5 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo5);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // add user with write permissions to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser5, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser5, DEFAULT_PASSWORD);

        // first user creates files
        createUsersAndUploadFiles(fifthNumberOfFiles, siteName);

        // first user logs out
        ShareUser.logout(drone);

    }

    /**
     * 1) Test user (site creator) logs in
     * 2) Test user (site creator) adds Top Site Contributor Dashlet to site's dashboard
     * 3) Checks the number of top site contributors is correct
     */
    @Test(groups = { "TopSiteContributorReport" })
    public void AONE_16001() throws Exception
    {
        // test user (site creator) logs in
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String siteName = getSiteName(testName);
        ShareUser.login(drone, testUser, testPassword);

        // test user (site creator) adds Top Site Contributor Dashlet to site's dashboard
        ShareUserDashboard.addDashlet(drone, siteName, Dashlets.TOP_SITE_CONTRIBUTOR_REPORT);
             
        TopSiteContributorDashlet topSiteContributorDashlet = ShareUserDashboard.getTopSiteContributorDashlet(drone, siteName);
        verifyDashletData(topSiteContributorDashlet, testName);
        
        //select Today option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarTodayOption();
        
        //Verify results
        verifyDashletData(topSiteContributorDashlet, testName);
        
        //select Last 7 days option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarLastSevenDaysOption();
        
        //Verify results
        verifyDashletData(topSiteContributorDashlet, testName);
        
        //select Past Year days option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarPastYearOption();
        
        //Verify results
        verifyDashletData(topSiteContributorDashlet, testName);
                
        //select Date Range option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarDateRangeOption();
        
        //Verify results
        verifyDashletData(topSiteContributorDashlet, testName);
        
    }
    
    
    /**
     * 1) Create test user
     * 2) Login as test user
     * 3) Create site
     * 4) Create user1
     * 5) Add user1 with write permissions to write to the site
     * 6) Test user logs out
     * 7) User1 logs in
     * 8) User1 creates txt files
     * 9) User1 logs out
     * 
     * @throws Exception
     */
    @Test(groups = { "DataPrepTopSiteContributorReport" })
    public void dataPrep_TopSiteContributor_AONE_16002() throws Exception
    {
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String[] testUserInfo = new String[] { testUser };
        String siteName = getSiteName(testName);

        int numberOfFiles = 1;
 
        // Create test user
        CreateUserAPI.createActivateUserAsTenantAdmin(drone, ADMIN_USERNAME, testUserInfo);

        // Login as created user
        ShareUser.login(drone, testUser, testPassword);

        // Create site
        SiteUtil.createSite(drone, siteName, AbstractUtils.SITE_VISIBILITY_PRIVATE);

        // first user
        String testUser1 = getUserNameForDomain(testName + "-0", DOMAIN_FREE);
        String[] testUserInfo1 = new String[] { testUser1 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, ADMIN_USERNAME, testUserInfo1);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // add user with write permissions to write to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser1, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser1, DEFAULT_PASSWORD);

        // first user creates files
        createUsersAndUploadFiles(numberOfFiles, siteName);

        // first user logs out
        ShareUser.logout(drone);

    }

    /**
     * 1) Collaborator logs in
     * 2) Collaborator adds Top Site Contributor Report Dashlet to site's dashboard
     * 3) Verify user can't customize the site dasboard      
     */
    @Test(groups = { "TopSiteContributorReport" })
    public void AONE_16002()
    {
        String testName = getTestName();
        String siteName = getSiteName(testName);
        String testUser1 = getUserNameForDomain(testName + "-0", DOMAIN_FREE);
        
        ShareUser.login(drone, testUser1, DEFAULT_PASSWORD);

        SiteDashboardPage siteDashBoard = ShareUser.openSiteDashboard(drone, siteName);
       
        //verify user can't customize the site dasboard
        try
        {
            siteDashBoard.getSiteNav().selectCustomizeSite();
            Assert.assertTrue(false, "Above line should have thrown page exception");
        }
        catch (NoSuchElementException e)
        {
            Assert.assertTrue(e.getMessage().startsWith( "Unable to locate element:"));
            ShareUser.logout(drone);

        }

    }
    
    
    
    /**
     * 1) Create test user
     * 2) Login as test user
     * 3) Create site
     * 4) Create user1
     * 5) Add user1 with write permissions to write to the site
     * 6) Test user logs out
     * 7) User1 logs in
     * 8) User1 creates txt files
     * 9) User1 logs out
     * 
     * @throws Exception
     */
    @Test(groups = { "DataPrepTopSiteContributorReport" })
    public void dataPrep_TopSiteContributor_AONE_16014() throws Exception
    {
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String[] testUserInfo = new String[] { testUser };
        String siteName = getSiteName(testName);

        int numberOfFiles = 1;
 
        // Create test user
        CreateUserAPI.createActivateUserAsTenantAdmin(drone, ADMIN_USERNAME, testUserInfo);

        // Login as created user
        ShareUser.login(drone, testUser, testPassword);

        // Create site
        SiteUtil.createSite(drone, siteName, AbstractUtils.SITE_VISIBILITY_PRIVATE);

        // first user
        String testUser1 = getUserNameForDomain(testName + "-0", DOMAIN_FREE);
        String[] testUserInfo1 = new String[] { testUser1 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, ADMIN_USERNAME, testUserInfo1);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // add user with write permissions to write to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser1, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser1, DEFAULT_PASSWORD);

        // first user creates files
        createUsersAndUploadFiles(numberOfFiles, siteName);

        // first user logs out
        ShareUser.logout(drone);

    }

    /**
     * 1) Test user (site creator) logs in
     * 2) Test user (site creator) adds Top Site Contributor Dashlet to site's dashboard
     * 3) Test user (site creator) selects date Range option from calendar and enters To and From dates in the past
     * 4) Verify chart is not displayed and No data found message is shown     
     */
    @Test(groups = { "TopSiteContributorReport" })
    public void AONE_16014()
    {
        // test user (site creator) logs in
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String siteName = getSiteName(testName);
        ShareUser.login(drone, testUser, testPassword);

        // test user (site creator) adds Top Site Contributor Dashlet to site's dashboard
        ShareUserDashboard.addDashlet(drone, siteName, Dashlets.TOP_SITE_CONTRIBUTOR_REPORT);
             
        TopSiteContributorDashlet topSiteContributorDashlet = ShareUserDashboard.getTopSiteContributorDashlet(drone, siteName);
     
        //select Date Range option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarDateRangeOption();
        topSiteContributorDashlet.renderDateDropDown(new RenderTime(maxWaitTime));
        
        //topSiteContributorDashlet.enterFromToDate("7/27/2012", "7/28/2012");
        topSiteContributorDashlet.enterFromToDate("27/7/2012", "28/7/2012");
        
        //Verify chart is not displayed and No data found message is shown
        topSiteContributorDashlet.clickOnChart();
        Assert.assertTrue(topSiteContributorDashlet.isNoDataFoundDisplayed());

    }   
    
    /**
     * 1) Create test user
     * 2) Login as test user
     * 3) Create site
     * 4) test user logs out
     * 
     * @throws Exception
     */
    @Test(groups = { "DataPrepTopSiteContributorReport" })
    public void dataPrep_TopSiteContributor_AONE_16015() throws Exception
    {
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String[] testUserInfo = new String[] { testUser };
        String siteName = getSiteName(testName);
 
        // Create test user
        CreateUserAPI.createActivateUserAsTenantAdmin(drone, ADMIN_USERNAME, testUserInfo);

        // Login as created user
        ShareUser.login(drone, testUser, testPassword);

        // Create site
        SiteUtil.createSite(drone, siteName, AbstractUtils.SITE_VISIBILITY_PRIVATE);

        //test user logs out
        ShareUser.logout(drone);

    }

    /**
     * 1) Test user (site creator) logs in
     * 2) Test user (site creator) adds Top Site Contributor Dashlet to site's dashboard
     * 3) Test user (site creator) selects all the options from the calendar and
     * 4) Verifies for each calendar option that the chart is not displayed and No data found message is shown     
     */
    @Test(groups = { "TopSiteContributorReport" })
    public void AONE_16015()
    {
        // test user (site creator) logs in
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String siteName = getSiteName(testName);
        ShareUser.login(drone, testUser, testPassword);

        // test user (site creator) adds Top Site Contributor Dashlet to site's dashboard
        ShareUserDashboard.addDashlet(drone, siteName, Dashlets.TOP_SITE_CONTRIBUTOR_REPORT);
        TopSiteContributorDashlet topSiteContributorDashlet = ShareUserDashboard.getTopSiteContributorDashlet(drone, siteName);
     
        //Verify chart is not displayed and No data found message is shown - Last 30 Days
        topSiteContributorDashlet.clickOnChart();
        Assert.assertTrue(topSiteContributorDashlet.isNoDataFoundDisplayed());

        //select Today option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarTodayOption();
        
        //Verify chart is not displayed and No data found message is shown
        topSiteContributorDashlet.clickOnChart();
        Assert.assertTrue(topSiteContributorDashlet.isNoDataFoundDisplayed());
        
        //select Last seven Days option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarLastSevenDaysOption();
        
        //Verify chart is not displayed and No data found message is shown
        topSiteContributorDashlet.clickOnChart();
        Assert.assertTrue(topSiteContributorDashlet.isNoDataFoundDisplayed());
        
        //select Past Year option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarPastYearOption();
        
        //Verify chart is not displayed and No data found message is shown
        topSiteContributorDashlet.clickOnChart();
        Assert.assertTrue(topSiteContributorDashlet.isNoDataFoundDisplayed());
        
        //select Date Range option from calendar drop down
        topSiteContributorDashlet.clickOnCalendarDropdown();
        topSiteContributorDashlet.clickCalendarDateRangeOption();
        topSiteContributorDashlet.renderDateDropDown(new RenderTime(maxWaitTime));
        
        //Verify chart is not displayed and No data found message is shown
        topSiteContributorDashlet.clickOnChart();
        Assert.assertTrue(topSiteContributorDashlet.isNoDataFoundDisplayed());

    }   
    
    /**
     * 1) Create test user
     * 2) Login as test user
     * 3) Create site
     * 4) Create user1
     * 5) Add user1 with write permissions to write to the site
     * 6) Test user logs out
     * 7) User1 logs in
     * 8) User1 creates txt files
     * 9) User1 logs out
     * 10) Steps 2,4,5,6,7,8,9 repeated for user2, user3, user4 and user5
     * 
     * @throws Exception
     */
    @Test(groups = { "DataPrepTopSiteContributorReport" })
    public void dataPrep_TopSiteContributor_AONE_16018() throws Exception
    {
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String[] testUserInfo = new String[] { testUser };
        String siteName = getSiteName(testName);

        // Create test user
        CreateUserAPI.createActivateUserAsTenantAdmin(drone, ADMIN_USERNAME, testUserInfo);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // test user creates site
        SiteUtil.createSite(drone, siteName, AbstractUtils.SITE_VISIBILITY_PRIVATE);

        // first user
        String testUser1 = getUserNameForDomain(testName + "-0", DOMAIN_FREE);
        String[] testUserInfo1 = new String[] { testUser1 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo1);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);
        
        // add user with write permissions to write to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser1, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser1, DEFAULT_PASSWORD);

        // first user creates files
        createUsersAndUploadFiles(firstNumberOfFiles, siteName);

        // first user logs out
        ShareUser.logout(drone);

        // second user
        String testUser2 = getUserNameForDomain(testName + "-2", DOMAIN_FREE);
        String[] testUserInfo2 = new String[] { testUser2 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo2);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // add user with write permissions to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser2, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser2, DEFAULT_PASSWORD);

        // second user creates files
        createUsersAndUploadFiles(secondNumberOfFiles, siteName);

        // second user logs out
        ShareUser.logout(drone);

        // third user
        String testUser3 = getUserNameForDomain(testName + "-3", DOMAIN_FREE);
        String[] testUserInfo3 = new String[] { testUser3 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo3);

        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);
        
        // add user with write permissions to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser3, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser3, DEFAULT_PASSWORD);

        // first user creates files
        createUsersAndUploadFiles(thirdNumberOfFiles, siteName);

        // third user logs out
        ShareUser.logout(drone);

        // fourth user
        String testUser4 = getUserNameForDomain(testName + "-4", DOMAIN_FREE);
        String[] testUserInfo4 = new String[] { testUser4 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo4);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // add user with write permissions to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser4, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser4, DEFAULT_PASSWORD);

        // fourth user creates files
        createUsersAndUploadFiles(fourthNumberOfFiles, siteName);

        // fourth user logs out
        ShareUser.logout(drone);

        // fifth user
        String testUser5 = getUserNameForDomain(testName + "-5", DOMAIN_FREE);
        String[] testUserInfo5 = new String[] { testUser5 };

        CreateUserAPI.createActivateUserAsTenantAdmin(drone, testUser, testUserInfo5);
        
        // Login as created test user
        ShareUser.login(drone, testUser, testPassword);

        // add user with write permissions to the site
        ShareUserMembers.inviteUserToSiteWithRole(drone, testUser, testUser5, siteName, UserRole.COLLABORATOR);

        // Inviting user logs out
        ShareUser.logout(drone);

        // Invited User logs in
        ShareUser.login(drone, testUser5, DEFAULT_PASSWORD);

        // first user creates files
        createUsersAndUploadFiles(fifthNumberOfFiles, siteName);

        // first user logs out
        ShareUser.logout(drone);

    }    
    
    /**
     * 1) Test user (site creator) logs in
     * 2) Test user (site creator) adds Top Site Contributor Dashlet to site's dashboard
     * 3) Checks the number of top site contributors is correct
     * 4) Remove dashlet from the dashboard
     * 5) Delete all files from site's document library
     * 6) Add the dashlet to the site's document library
     * 7) Verify chart is not displayed and No data found message is shown 
     *  
     */
    @Test(groups = { "TopSiteContributorReport" })
    public void AONE_16018() throws Exception
    {
        // test user (site creator) logs in
        String testName = getTestName();
        String testUser = getUserNameForDomain(testName, DOMAIN_FREE);
        String siteName = getSiteName(testName);
        ShareUser.login(drone, testUser, testPassword);

        // test user (site creator) adds Top Site Contributor Dashlet to site's dashboard
        ShareUserDashboard.addDashlet(drone, siteName, Dashlets.TOP_SITE_CONTRIBUTOR_REPORT);
             
        //Checks the number of top site contributors is correct
        TopSiteContributorDashlet topSiteContributorDashlet = ShareUserDashboard.getTopSiteContributorDashlet(drone, siteName);
        verifyDashletData(topSiteContributorDashlet, testName);
        
        //remove dashlet from the dashboard
        ShareUserDashboard.removeDashlet(drone, Dashlets.TOP_SITE_CONTRIBUTOR_REPORT, siteName);
        ShareUser.openDocumentLibrary(drone);
        
        //delete all the files from site's document library
        ShareUser.deleteAllContentFromDocumentLibrary(drone);
         
        //add the dashlet to the site's document library
        ShareUserDashboard.addDashlet(drone, siteName, Dashlets.TOP_SITE_CONTRIBUTOR_REPORT);
        topSiteContributorDashlet = ShareUserDashboard.getTopSiteContributorDashlet(drone, siteName);
        
        //Verify chart is not displayed and No data found message is shown 
        topSiteContributorDashlet.clickOnChart();
        Assert.assertTrue(topSiteContributorDashlet.isNoDataFoundDisplayed());

    }
    
    /**
     * Uploads files to site's document library
     * 
     * @param numberOfFiles
     * @param siteName
     * @throws Exception
     */
    private void createUsersAndUploadFiles(int numberOfFiles, String siteName) throws Exception
    {
        String[] userFiles = new String[numberOfFiles];
        for (int i = 0; i < userFiles.length; i++)
        {
            userFiles[i] = getFileName(testName + "_" + i + "." + "txt");
        }

        ShareUser.openSitesDocumentLibrary(drone, siteName);

        // UpLoad Files
        for (int index = 0; index <= userFiles.length - 1; index++)
        {
            String[] fileInfo = { userFiles[index] };
            ShareUser.uploadFileInFolder(drone, fileInfo);
        }

    }
    
    /**
     * Verifies that dashlat displays correct data
     * 
     * @param topSiteContributorDashlet
     * @throws Exception
     */
    private void verifyDashletData(TopSiteContributorDashlet topSiteContributorDashlet, String testName) throws Exception
    {
        List<String> users = topSiteContributorDashlet.getTooltipUsers();
        List<String> usersData = topSiteContributorDashlet.getTooltipUserData();
        
        String testUser1 = getUserNameForDomain(testName + "-0", DOMAIN_FREE);
        String testUser2 = getUserNameForDomain(testName + "-2", DOMAIN_FREE);
        String testUser3 = getUserNameForDomain(testName + "-3", DOMAIN_FREE);
        String testUser4 = getUserNameForDomain(testName + "-4", DOMAIN_FREE);
        String testUser5 = getUserNameForDomain(testName + "-5", DOMAIN_FREE);

        Assert.assertTrue(users.contains(testUser1));
        Assert.assertTrue(users.contains(testUser2));
        Assert.assertTrue(users.contains(testUser3));
        Assert.assertTrue(users.contains(testUser4));
        Assert.assertTrue(users.contains(testUser5));        
        
        Assert.assertEquals(usersData.size(), 5);
        
        for(String userData : usersData)
        {
           String [] tokens = userData.split("-");
           String user = tokens[0];
           String fileCount = tokens[1];
                      
           if (user.trim().equalsIgnoreCase(testUser1))
           {
               Assert.assertEquals(Integer.parseInt(fileCount), firstNumberOfFiles);
           }
           
           if (user.trim().equalsIgnoreCase(testUser2))
           {
               Assert.assertEquals(Integer.parseInt(fileCount), secondNumberOfFiles);
           }
           
           if (user.trim().equalsIgnoreCase(testUser3))
           {
                Assert.assertEquals(Integer.parseInt(fileCount), thirdNumberOfFiles);
           }
          
           if (user.trim().equalsIgnoreCase(testUser4))
           {
                Assert.assertEquals(Integer.parseInt(fileCount), fourthNumberOfFiles);
           }

           if (user.trim().equalsIgnoreCase(testUser5))
           {
                Assert.assertEquals(Integer.parseInt(fileCount), fifthNumberOfFiles);
           }
            
        }                
    }
}
