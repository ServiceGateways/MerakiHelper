##############################################################################################	
# Imports
##############################################################################################	
#MerakiChecksSettings.py
modules = ["sys","os","datetime","csv","pathlib","argparse","requests","json","time","meraki"]
for library in modules:
	try:
	    exec("import {module}".format(module=library))
	except Exception as e:
	    print("This module is required, but not present install this module - ",e)
	    sys.exit()
try:
	from prettytable import PrettyTable #For Log table output
except Exception as e:
	print("This module is required, but not present install this module - ",e)
	sys.exit()
try:
	import pandas as pd #Used to make excel files... also needs openpyxl
except Exception as e:
	print("This module is required, but not present install this module - ",e)
	sys.exit()
try:
	from simplecrypt import encrypt, decrypt #Extract API Keys
except Exception as e:
	print("This module is required, but not present install this module - ",e)
	sys.exit()
try:
	from base64 import b64encode, b64decode #Coding formats
except Exception as e:
	print("This module is required, but not present install this module - ",e)
	sys.exit()
try:
	from dotenv import load_dotenv
except Exception as e:
	print("This module is required, but not present install this module - ",e)
	sys.exit()
##############################################################################################	
# End of imports
##############################################################################################	

	
############################################################
#Variables...
#############################################################
Devmode=False

Org_payload = None
API_URLPrefix = "https://api.meraki.com/api/v1/organizations/" 

RWmode=False #default passive mode script is ran in

#Required for UMS VMB-IAM Internal User Access
x509certSha1Fingerprint = "10:1D:AE:5F:0B:B3:27:CB:FB:C8:56:20:AD:F0:6F:70:70:56:95:70"
sloLogoutUrl = "https://ums.virginmediabusiness.co.uk/admin/launchpad"

#SAML Admin roles, define the access, role is passed in token on login. Required for Internal User Access
AdminRWname = "Meraki VMB Admin"
AdminRWaccess = "full"
AdminROname = "Meraki VMB Read Only"
AdminROaccess = "read-only"

#Local admins as a list of directories
adminA = {}
adminA["name"] = "VMO2MerakiSupportA@virginmedia.co.uk"
adminA["email"] = "vmo2merakisupporta@virginmedia.co.uk"
adminA["orgAccess"] = "read-only"
adminA["tags"] = "[]"
adminA["located"] = False
	
adminB = {}
adminB["name"] = "VMO2MerakiSupportB@virginmedia.co.uk"
adminB["email"] = "vmo2merakisupportb@virginmedia.co.uk"
adminB["orgAccess"] = "full"
adminB["tags"] = "[]"
adminB["located"] = False

adminC = {}
adminC["name"] = "VMO2MerakiSupportC@virginmedia.co.uk"
adminC["email"] = "vmo2merakisupportc@virginmedia.co.uk"
adminC["orgAccess"] = "full"
adminC["tags"] = "[]"	
adminC["located"] = False

adminD = {}
adminD["name"] = "VMO2MerakiSupportD@virginmedia.co.uk"
adminD["email"] = "vmo2merakisupportd@virginmedia.co.uk"
adminD["orgAccess"] = "full"
adminD["tags"] = "[]"
adminD["located"] = False

Localadmins = [adminA, adminB, adminC, adminD]

#list for log entries
LoggingList = []
LoggingListUplinks = []
#CSV Export file name 

###############################################################################################
#End of Variables
##############################################################################################	


##############################################################################################	
# Functions... some hardcoded, not really functions, but make main code neater
##############################################################################################	
def ReadyAPIinterface(APIKey):
	dashboard = meraki.DashboardAPI(APIKey)
	return(dashboard)

def GetAPIKey():
	load_dotenv(dotenv_path="/usr/local/scripts/.meraki.env") 
	APIKey=API(os.getenv('APIKeyUserName'),os.getenv('APIKeyStored'))
	return(APIKey)

def GetOrgs(dashboard):
	Org_response = dashboard.organizations.getOrganizations()
	return(Org_response)
##############################################################################################	

def GetHeaders():
	print("Decrypting API Keys...")
	# Build headers for API call
	headers = {}
	headers["Content-Type"] = "application/json"
	headers["Accept"] = "application/json"
	load_dotenv(dotenv_path="/usr/local/scripts/.meraki.env") 
	APIKey=API(os.getenv('APIKeyUserName'),os.getenv('APIKeyStored'))
	headers["X-Cisco-Meraki-API-Key"] = eval("APIKey")
	return(headers)
##############################################################################################	
###  BIG FUNCTION TO REVIEW OR FIX ORGS #########	
##############################################################################################	
	def UpdateLocalAdmin(LocalAdminUserID, OrgID, LocalAdminName, LocalAdminAccess):
		LocalAdminUpdate_suffix = "/admins/"
		LocalAdminUpdate_url =  API_URLPrefix + OrgID + LocalAdminUpdate_suffix + LocalAdminUserID	
		LocalAdminUpdatePayload = {}
		LocalAdminUpdatePayload["name"] = LocalAdminName
		LocalAdminUpdatePayload["orgAccess"] = LocalAdminAccess 
		LocalAdminUpdatePayload["tags"] = None
		LoggingAdd("Org admins: updating", "Ok", Orgs.get('name'),Orgs.get('id'))	
		PushLocalAdminUpdate = requests.request('PUT', LocalAdminUpdate_url, headers=headers, data = json.dumps(LocalAdminUpdatePayload))
		LoggingAdd("...org admin update complete", "Ok", Orgs.get('name'),Orgs.get('id'))	
		return PushLocalAdminUpdate.status_code
		##############################################################
		#Define function for creating the local admin accounts if needed
	def CreateLocalAdmin(OrgID, LocalAdminName, LocalAdminAccess, LocalAdminEmail):
		CreateLocalAdmin_suffix = "/admins/"
		CreateLocalAdmin_url =  API_URLPrefix + OrgID + CreateLocalAdmin_suffix	
		CreateLocalAdminPayload = {}
		CreateLocalAdminPayload["name"]= LocalAdminName
		CreateLocalAdminPayload["email"]= LocalAdminEmail
		CreateLocalAdminPayload["orgAccess"]= LocalAdminAccess
		CreateLocalAdminPayload["tags"]= None
		LoggingAdd("Org admins: creating", "Ok", Orgs.get('name'),Orgs.get('id'))	
		CreateLocalAdminresponse = requests.request('POST', CreateLocalAdmin_url, headers=headers, data = json.dumps(CreateLocalAdminPayload))
		return CreateLocalAdminresponse.status_code	

def BigLoop(RWmode, OrgResponse, FixOrg):
	#Start mega loop - looping through orgs
	for idx, Orgs in enumerate(OrgResponse):
		if RWmode == True:
			if Orgs.get('id') != str(FixOrg):
				continue
		runningxxx(idx+1, OrgResponse) #Show progress on screen
		print("Org:  ", Orgs.get('name'))
		LoggingAdd("Analysing org.....", "Ok", Orgs.get('name'), Orgs.get('id'))	
		#Check if API access is enabled for org if not log and skip
		API_on = Orgs.get('api')
		if API_on.get('enabled') == False:
			LoggingAdd("API access: disabled", "Err", Orgs.get('name'),Orgs.get('id'))
			continue
		LoggingAdd("API org access: enabled", "Ok", Orgs.get('name'),Orgs.get('id'))	
		#############################################################
		#Get the Org admin list
		OrgAdminResponse = dashboard.organizations.getOrganizationAdmins(Orgs.get('id'))
		##############################################################
		#Loop through admins and check if correct accounts are there.
		#for OrgAdmins in OrgAdminResponse:
		breakout = False
		showaccountonce = False
		for admins in OrgAdminResponse:
			for locals in Localadmins:
				#print(Localadmins[Localadmins.index(locals)].get('email'))
				if Localadmins[Localadmins.index(locals)].get('email') == os.getenv('APIKeyUserName'):
					#Found the account with which we are APIing into Meraki
					#Does it have RO or RW?
					if Localadmins[Localadmins.index(locals)].get('orgAccess') == "read-only" and RWmode==True:
						#account doesnt have enough juice
						LoggingAdd("API account does not have RW access.... aborting", "Err", Orgs.get('name'),Orgs.get('id'))	
						breakout = True
						break
					if showaccountonce == False:
						LoggingAdd("API account: RW", "OK", Orgs.get('name'),Orgs.get('id'))	
						showaccountonce = True
						#Attempt small push to org to test access
				if breakout == True:
					break
				if OrgAdminResponse[OrgAdminResponse.index(admins)].get('email') == locals.get('email'):
					#Found one of the VMB accounts
					
					Localadmins[Localadmins.index(locals)].update({"located":True})
					if Localadmins[Localadmins.index(locals)].get('name') != locals.get('name'):
						#The name is wrong, fix it.
						if RWmode==True:
							UpdateLocalAdminOutput = UpdateLocalAdmin(LocalAdminUserID = admins.get('id'), OrgID = Orgs.get('id') , LocalAdminName = locals.get('name'), LocalAdminAccess = locals.get('orgAccess'))
	
						if UpdateLocalAdminOutput.str != requests.codes.ok: #This makes no sense
							print("\t Something went wrong with this request")
							print("\t Error code was retunred:", UpdateLocalAdminOutput.str )
							print("\t Skipping this org, will need to be fixed manually")
							continue
					if Localadmins[Localadmins.index(locals)].get('orgAccess') != locals.get('orgAccess'):
						#The orgAccess in wrong, fix it.
						if RWmode == True:
							UpdateLocalAdmin(LocalAdminUserID = admins.get('id'), OrgID = Orgs.get('id') , LocalAdminName = locals.get('name'), LocalAdminAccess = locals.get('orgAccess'))
						
		#So by here any accounts located have been fixed, but are any missing	
		for locals in Localadmins:
			if Localadmins[Localadmins.index(locals)].get('located') == False:
				#One of the local accounts is missing, put it back
				LoggingAdd((locals.get('email'), " is missing from org "), "Err", Orgs.get('name'),Orgs.get('id'))	
				if RWmode==True:
					CreateLocalAdminOutput = CreateLocalAdmin(OrgID = Orgs.get('id'), LocalAdminName = locals.get('name'), LocalAdminAccess = locals.get('orgAccess'), LocalAdminEmail = locals.get('email') )
				if CreateLocalAdminOutput == False: #This makes no sense
					print("\t Something went wrong with this request")
					print("\t Error code was retunred:", CreateLocalAdminOutput.str )
					print("\t Skipping this org, will need to be fixed manually")
					continue
	#############################################################
		# First routine... check the security rules for this org 	
		LoginResponse = dashboard.organizations.getOrganizationLoginSecurity(Orgs.get('id'))
		
		#Test security rules
		PushNewLoginPolicy = False
		if LoginResponse.get('enforcePasswordExpiration') == False:
			PushNewLoginPolicy = True
		if LoginResponse.get('passwordExpirationDays') != 32:
			PushNewLoginPolicy = True	
		if LoginResponse.get('enforceDifferentPasswords') == False:
			PushNewLoginPolicy = True
		if LoginResponse.get('numDifferentPasswords') != 10:
			PushNewLoginPolicy = True
		if LoginResponse.get('enforceStrongPasswords') == False:
			PushNewLoginPolicy = True
		if LoginResponse.get('enforceAccountLockout') == False:
			PushNewLoginPolicy = True
		if LoginResponse.get('accountLockoutAttempts') != 5:
			PushNewLoginPolicy = True
		if LoginResponse.get('enforceIdleTimeout') ==False:
			PushNewLoginPolicy = True
		if LoginResponse.get('idleTimeoutMinutes') != 15:
			PushNewLoginPolicy = True
		if LoginResponse.get('enforceTwoFactorAuth') == False:
			PushNewLoginPolicy = True	
		if LoginResponse.get('enforceLoginIpRanges') == True:
			PushNewLoginPolicy = True
		#Do we need to push a new login policy?
		if PushNewLoginPolicy == True:
			if RWmode == False:
				LoggingAdd("Login Security: failed", "Err", Orgs.get('name'),Orgs.get('id'))		
			if RWmode == True:
				#Push new policy
				LoggingAdd("Login Security: updating", "Ok", Orgs.get('name'),Orgs.get('id'))	
				response = dashboard.organizations.updateOrganizationLoginSecurity(Orgs.get('id'), enforcePasswordExpiration=True, passwordExpirationDays=32, enforceDifferentPasswords=True, numDifferentPasswords=10, enforceStrongPasswords=True, enforceAccountLockout=True, accountLockoutAttempts=5, enforceIdleTimeout=True, idleTimeoutMinutes=15, enforceTwoFactorAuth=True, enforceLoginIpRanges=True, loginIpRanges=[], apiAuthentication={'ipRestrictionsForKeys': {'enabled': False, 'ranges': []}})
							
			#Do we need to push a new login policy?
			if PushNewLoginPolicy == False:
				LoggingAdd("Login Security: ok", "Ok", Orgs.get('name'),Orgs.get('id'))	
			PushNewLoginPolicy = False	
	#############################################################
		#2nd routine check the IDp settings
		#Build URL to capture IDp settings
		SamlResponse = dashboard.organizations.getOrganizationSaml(Orgs.get('id'))
		#Prepare a small function to be used if IdP disabled or missing
		def SetupIPpInternal(OrgID):
			LoggingAdd("IdP: Updating", "Ok", Orgs.get('name'),Orgs.get('id'))	
			PushIDp = dashboard.organizations.createOrganizationSamlIdp(Orgs.get('id'), x509certSha1Fingerprint, sloLogoutUrl)
			return PushIDp
		#Is SAML / IdP disabled? If so enable it and call function
		if SamlResponse.get('enabled') == False:
			if RWmode == False:
				LoggingAdd("SAML enabled: failed", "Err", Orgs.get('name'),Orgs.get('id'))		
			if RWmode == True:
				LoggingAdd("SAML enabled: updating", "Ok", Orgs.get('name'),Orgs.get('id'))	
				response = dashboard.organizations.updateOrganizationSaml(Orgs.get('id'), enabled=True)
			if RWmode == False:
				LoggingAdd("SAML enabled: failed", "Err", Orgs.get('name'),Orgs.get('id'))		
	    #############################################################
		#Cycle through configured IdPs attemp to find 
		#############################################################
		IdP_Configured = dashboard.organizations.getOrganizationSamlIdps(Orgs.get('id'))
		IdPsFound = False
		IdPsConfiguredCorrect = False
		for IdPs in IdP_Configured:
			IdPsID = IdP_Configured[IdP_Configured.index(IdPs)].get('idpId')
			if IdPs.get('x509certSha1Fingerprint') == eval("x509certSha1Fingerprint"):
				IdPsFound = True
				if IdPs.get('sloLogoutUrl') == eval("sloLogoutUrl"):
					IdPsConfiguredCorrect = True
					continue
				#Found the IdP by matching the x509 cert byt url is wrong... fix it with update
				if RWmode == False:
					LoggingAdd("IdP Integration: failed", "Err", Orgs.get('name'),Orgs.get('id'))		
				if RWmode == True:	
					LoggingAdd("IdP Integration: updating", "Ok", Orgs.get('name'),Orgs.get('id'))	
					UpdateIdP = dashboard.organizations.updateOrganizationSamlIdp(Orgs.get('id'), IdPsID, x509certSha1Fingerprint, sloLogoutUrl)
		#If IdPsFound == False then we didnt find the IdP settings, so put them back
		if IdPsFound == False:
			if RWmode == False:
				LoggingAdd("IdP Integration: failed", "Err", Orgs.get('name'),Orgs.get('id'))		
			if RWmode == True:	
				SetupIPpInternal(OrgID=Orgs.get('id'))
	#############################################################
		#get the saml roles and check if they are set correctly
		SAMLroleResponse = dashboard.organizations.getOrganizationSamlRoles(Orgs.get('id'))
		FoundMerakiAdmin = False
		FoundMerakiRoAdmin = False
		#Cycle through list and check if they are they and/or correctly configured
		for SAMLrole in SAMLroleResponse:
			if SAMLrole.get('role') == AdminRWname:
				FoundMerakiAdmin = True
				if SAMLrole.get('orgAccess') != AdminRWaccess:
					#make org access full
					UpdateAdminResponse=UpdateAdmin(RoleID = SAMLrole.get('id'), OrgID = Orgs.get('id'), Access = eval("AdminRWaccess"))
			if SAMLrole.get('role') == AdminROname:
				FoundMerakiRoAdmin = True
				if SAMLrole.get('orgAccess') != AdminROaccess:
					#make org access read-only
					UpdateAdminResponse=UpdateAdmin(RoleID = SAMLrole.get('id') ,OrgID = Orgs.get('id'), Access = AdminROaccess)
		#If they arent found put them in	
		if FoundMerakiAdmin == False:
			#create role for Meraki Admin
			if RWmode == False:
				LoggingAdd("Org admins: failed", "Err", Orgs.get('name'),Orgs.get('id'))		
			if RWmode == True:	
				CreateAdminResponse = CreateAdmin(OrgID = Orgs.get('id'), AdminName = eval("AdminRWname"), Access = eval("AdminRWaccess"))
		if FoundMerakiRoAdmin == False:
			#create role for Meraki RO admin
			if RWmode == False:
				LoggingAdd("Org admins: failed", "Err", Orgs.get('name'),Orgs.get('id'))		
			if RWmode == True:
				CreateAdminResponse = CreateAdmin(OrgID = Orgs.get('id'), AdminName = eval("AdminROname"), Access = eval("AdminROaccess"))
		#Move to next org, avoid Meraki API Gateway throttling. Basic, but effective
		time.sleep(0.2)
	
	
##############################################################################################	
# *** BIG DELETE FUNCTIONS ***
##############################################################################################	

def DeleteOrg(OrgID, OrgResponse):
	
	for idx, Orgs in enumerate(OrgResponse):
		if Orgs.get('id') != str(OrgID):
			continue
		print(" ")
		print("Org:  ", Orgs.get('name'))
		print(" ")
		#Double check before we delete
		print("*** WARNING: THERE IS NO COMING BACK FROM THIS ***")
		print(" ")
		ConfirmName = input("Please confirm the org NAME you are attempting to delete (or ctrl-x to abort): ")
		if ConfirmName != Orgs.get('name'):
			print("Wrong name provided... safety abort")
			sys.exit()		
		
		LoggingAdd("Analysing org.....", "Ok", Orgs.get('name'), Orgs.get('id'))	
	
		#Check if API access is enabled for org if not log and skip
		API_on = Orgs.get('api')
		if API_on.get('enabled') == False:
			LoggingAdd("API access: disabled", "Err", Orgs.get('name'),Orgs.get('id'))
			continue
		LoggingAdd("API org access: enabled", "Ok", Orgs.get('name'),Orgs.get('id'))	
	#############################################################
		#Get the Org admin list
		OrgAdminResponse = dashboard.organizations.getOrganizationAdmins(Orgs.get('id'))
	##############################################################
		#Loop through admins and check if correct accounts are there.
		#for OrgAdmins in OrgAdminResponse:
		breakout = False
		showaccountonce = False
		for admins in OrgAdminResponse:
			for locals in Localadmins:
				if Localadmins[Localadmins.index(locals)].get('email') == os.getenv('APIKeyUserName'):
					#Found the account with which we are APIing into Meraki
					#Does it have RO or RW?
					if Localadmins[Localadmins.index(locals)].get('orgAccess') == "read-only" and RWmode==True:
						#account doesnt have enough juice
						LoggingAdd("API account does not have RW access.... aborting", "Err", Orgs.get('name'),Orgs.get('id'))	
						breakout = True
						break
					if showaccountonce == False:
						LoggingAdd("API account: RW", "OK", Orgs.get('name'),Orgs.get('id'))	
						showaccountonce = True
			##############################################################
			#This should delete any admin which is not needed					
			if admins.get('email') != os.getenv('APIKeyUserName'):
				#delete user
				DeleteResponse = dashboard.organizations.deleteOrganizationAdmin(Orgs.get('id'), admins.get('id'))
	##############################################################
		#Turn off SAML
		PushNewSaml = dashboard.organizations.updateOrganizationSaml(Orgs.get('id'), enabled=False)
	#############################################################
	#Delete Networkds
		Networks = dashboard.organizations.getOrganizationNetworks(Orgs.get('id'), total_pages='all')
		for net in Networks:
			NetDelresponse = dashboard.networks.deleteNetwork(net.get('id'))
	#############################################################
	#Delete all templates
		templates = dashboard.organizations.getOrganizationConfigTemplates(Orgs.get('id'))	
		for templ in templates:
			templDelresponse = dashboard.organizations.deleteOrganizationConfigTemplate(Orgs.get('id'), templ.get('id'))	
	#############################################################
	#Delete Org
		DeleteResponse = dashboard.organizations.deleteOrganization(Orgs.get('id'))
		#print("DeleteResponse",DeleteResponse)
		LoggingAdd("Deleting Org", "OK", Orgs.get('name'),Orgs.get('id'))		
##############################################################################################	
# *** END OF DELET ORG FUNCTION ***
##############################################################################################	


##############################################################################################	
#Review the LoggingList, strip out heavy dumps and creates a easy read report
def Logging2CSVandXLS(prefix): #Convert the Log file into a short report.
	CSVdate = str((datetime.datetime.now()).strftime("%d%m%Y%H%M"))
	CSVfilename = prefix + CSVdate +".csv"
	Xlsfilename = prefix + CSVdate +".xlsx"
	#get a Unique list of orgs from the logs inc. org id and place into a list of dic
	OrgListfromLogs=[]
	for LoggingListentries in LoggingList:
		OrgListfromLogs.append(LoggingListentries.get('OrgRef') )
	UniqueOrgListfromLogs = list(dict.fromkeys(OrgListfromLogs))
	UniqueOrgsIncID=[]
	for LoggingListEntries in LoggingList:
		for UniqueOrgs in UniqueOrgListfromLogs:
			if str(LoggingListEntries['OrgRef']) == str(UniqueOrgs):
				if (next((item for item in UniqueOrgsIncID if item["OrgRef"] == LoggingListEntries['OrgRef']),None)) == None:
					PrepOrgDic={}
					PrepOrgDic['Org'] = LoggingListEntries.get('Org')
					PrepOrgDic['OrgRef'] = LoggingListEntries.get('OrgRef')			
					UniqueOrgsIncID.append(PrepOrgDic)			
	#assume each org is compliant
	ListofDic_UniqueOrgs=[]
	for UniqueOrgs in UniqueOrgsIncID:
		PrepOrgDic={}
		PrepOrgDic['Org'] = UniqueOrgs.get('Org')
		PrepOrgDic['OrgRef'] = (UniqueOrgs.get('OrgRef'))
		PrepOrgDic['Compliance'] = "Compliant"
		PrepOrgDic['Issues'] = ""
		ListofDic_UniqueOrgs.append(PrepOrgDic)
	#For each log entry look for entries against each unique org and see if it wasnt compliant
	#This ony captures the last issue in the log, not all of them.
	for LogEntries in LoggingList:
		#print(LogEntries.get('Org'))
		for UniqueOrgs in ListofDic_UniqueOrgs:
			if LogEntries.get('Org') == UniqueOrgs.get('Org'):
				if LogEntries.get('StatusCode') != "Ok":
					PrepOrgDic={}
					PrepOrgDic['Org'] = UniqueOrgs.get('Org')
					PrepOrgDic['OrgRef'] = (UniqueOrgs.get('OrgRef'))
					PrepOrgDic['Compliance'] = "Un-compliant"
					PrepOrgDic['Issues'] = LogEntries.get('Description')
					UniqueOrgs.update(PrepOrgDic)
	#For Loop ends... write to file
	#Make CSV File
	CSVHeaders = ['Org','OrgRef', 'Compliance', 'Issues']
	with open(CSVfilename, 'w') as csvfile:
		writer = csv.DictWriter(csvfile, fieldnames = CSVHeaders)
		writer.writeheader()
		writer.writerows(ListofDic_UniqueOrgs)
	#Make XLS file
	df = pd.DataFrame.from_dict(ListofDic_UniqueOrgs)
	df.to_excel(str(Xlsfilename))
	FullFilePath = str(pathlib.Path(__file__).parent.resolve())+"/"+str(Xlsfilename)
	print("Full report available at: ",FullFilePath)
##############################################################################################	
#Time stamps and adds things to the logging list
def LoggingAdd(Description, StatusCode, Org, OrgRef):
	now = datetime.datetime.now()
	#Log only hold the last 300 entries
	while (len(LoggingList) >= 300):
		LoggingList.pop(0)
	#Blank a directory for tracking logging items
	LoggingDic = {}
	LoggingDic["Date"] = str(now.strftime("%d/%m/%Y"))
	LoggingDic["Time"] = str(now.strftime("%H:%M:%S"))
	LoggingDic["Description"] = Description
	LoggingDic["StatusCode"] = StatusCode
	LoggingDic["Org"] = Org
	LoggingDic["OrgRef"] = OrgRef
	#Add new log entry to list
	LoggingList.append(LoggingDic)
	return(LoggingList)
##############################################################################################	
#Prints on screen the logging List
def LoggingPrint():
	print("APIs pushed using: ", os.getenv('APIKeyUserName'))
	LogTable = PrettyTable(['Date', 'Time', 'Description', 'StatusCode', 'Org', 'OrgRef'],align='l',valign='t')
	for LogEntries in LoggingList:
		LogTable.add_row([LogEntries.get('Date'), LogEntries.get('Time'),LogEntries.get('Description'),LogEntries.get('StatusCode'),LogEntries.get('Org'),LogEntries.get('OrgRef')])
	print(LogTable)
##############################################################################################	
#small add new role function to create admins
def CreateAdmin(OrgID, AdminName, Access):
	SAMLrole_url_suffix = "/samlRoles"
	SAMLrole_url =  API_URLPrefix + OrgID + SAMLrole_url_suffix		
	SAMLrolePayload = ''' {"role":"''' + AdminName + '''","orgAccess":"''' + Access +'''","networks": [],
   	"tags": []}'''
	#LoggingAdd("SAML role: creating", "Ok", Orgs.get('name'),Orgs.get('id'))	
	PushSAMLrole = requests.request('POST', SAMLrole_url, headers=headers, data = SAMLrolePayload)	
	return PushSAMLrole
##############################################################################################
#small update role function to Update admin role
def UpdateAdmin(RoleID, OrgID, Access):
	SAMLroleUpdate_suffix = "/samlRoles/"
	SAMLroleUpdate_url =  API_URLPrefix + OrgID + SAMLroleUpdate_suffix + RoleID		
	SAMLroleUpdatePayload = ''' {"orgAccess":"''' + Access +'''","networks": [],
   	"tags": []}'''
	LoggingAdd("SAML role: updating", "Ok", Orgs.get('name'),Orgs.get('id'))			
	PushSAMLroleUpdate = requests.request('PUT', SAMLroleUpdate_url, headers=headers, data = SAMLroleUpdatePayload)
	return PushSAMLroleUpdate
##############################################################################################
#Clear screen 
def screen_clear():
	# for mac and linux(here, os.name is 'posix')
	if os.name == 'posix':
		_ = os.system('clear')
	else:
	# for windows platfrom
		_ = os.system('cls')
##############################################################################################
# Function shows program is still running through orgs
def runningxxx(LoopNumber,OrgResponse):
	screen_clear()
	print("Running",'.' * LoopNumber, flush=True)
	print(LoopNumber, "of", len((OrgResponse)))

##############################################################################################
# Pull arguments from command line
def parseArguments():
    # Create argument parser
    parser = argparse.ArgumentParser()
    # Optional arguments
    parser.add_argument("--fix", help="Fix an org not in compliance <specify Org ID>", type=int)
    parser.add_argument("--remove", help="Delete this empty org <specify Org ID>", type=int)
   
    parser.add_argument("--search", help="Search org names for <string>", type=str)
    parser.add_argument("--list", help="Lists all orgs the script has access to", action="store_true")
    parser.add_argument("--up", help="List MX Appliances with WAN interface issues", action="store_true")
    parser.add_argument("--review", help="Compliance check for ops", action="store_true")
    parser.add_argument("--version", action="version", version='%(prog)s - Version 2.1')
    #parser.add_argument("--api", help="Plain text API", type=str)
    #parser.add_argument("--usr", help="Plain text usrname", type=str)
    # Parse arguments
    args = parser.parse_args()
    parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    return args

##############################################################################################
#Prepare API
def API(a,b):
	if Devmode== False:
		c = b64decode(b)
		p = decrypt(a, c)
		return(p.decode("utf-8"))
##############################################################################################
def APIStore(a, b):
	c = encrypt(a, b)
	encoded_c = b64encode(c)
	return(encoded_c)
##############################################################################################
def	ListOrgAccess(OrgResponse):
	for idx, Orgs in enumerate(OrgResponse):
		if Orgs == "end":
			continue
		runningxxx(idx+1,OrgResponse) #Show progress on screen
		LoggingAdd("Analysing org.....", "Ok", Orgs.get('name'), Orgs.get('id'))	
##############################################################################################
def FindOrgAndList(OrgResponse, argssearch):
	foundsomething = False
	for idx, Orgs in enumerate(OrgResponse):
		if Orgs == "end":
			continue
		runningxxx(idx+1,OrgResponse) #Show progress on screen
		if argssearch.lower() in Orgs.get('name').lower(): 
			foundsomething = True
			LoggingAdd("Analysing org.....", "Ok", Orgs.get('name'), Orgs.get('id'))	
	return foundsomething
##############################################################################################
def GetUplinkStatus(OrgID):
	Uplinkresponse = dashboard.appliance.getOrganizationApplianceUplinkStatuses(OrgID, total_pages='all')
	return(Uplinkresponse)
##############################################################################################	
def LoggingAddUplinks(Serial,Interface, StatusCode, Org, OrgRef):
	now = datetime.datetime.now()
	#Log only hold the last 300 entries
	while (len(LoggingListUplinks) >= 5000):
		LoggingListUplinks.pop(0)
	#Blank a directory for tracking logging items
	LoggingDic = {}
	LoggingDic["Date"] = str(now.strftime("%d/%m/%Y"))
	LoggingDic["Time"] = str(now.strftime("%H:%M:%S"))
	LoggingDic["Serial"] = Serial
	LoggingDic["Interface"] = Interface
	LoggingDic["StatusCode"] = StatusCode
	LoggingDic["Org"] = Org
	LoggingDic["OrgRef"] = OrgRef
	#Add new log entry to list
	LoggingListUplinks.append(LoggingDic)
	return(LoggingListUplinks)
##############################################################################################	
#Prints on screen the logging List
def LoggingUplinkPrint():
	screen_clear()
	print("APIs pushed using: ", os.getenv('APIKeyUserName'))
	LogTable = PrettyTable(['Date', 'Time', 'Serial','Interface', 'StatusCode', 'Org', 'OrgRef'],align='l',valign='t')
	for LogEntries in LoggingListUplinks:
		LogTable.add_row([LogEntries.get('Date'), LogEntries.get('Time'),LogEntries.get('Serial'),LogEntries.get('Interface'),LogEntries.get('StatusCode'),LogEntries.get('Org'),LogEntries.get('OrgRef')])
	print(LogTable)
##############################################################################################		
def DeviceUp(uplinks,serial,name,id):
	DeviceStatus=True
	for interfaces in uplinks:
		if interfaces.get('status') != "active":
			DeviceStatus=False
			LoggingAddUplinks(serial,"***DEVICE WARNING***", " ", name, id)
			return(DeviceStatus)
	return(DeviceStatus)
##############################################################################################		
def CheckUP(OrgResponse):
	for idx, Orgs in enumerate(OrgResponse):
		if Orgs == "end":
			continue
		runningxxx(idx+1,OrgResponse) #Show progress on screen
		#get uplinks
		Uplinkresponse=GetUplinkStatus(Orgs.get('id'))		
		for idx, appliances in enumerate(Uplinkresponse):
			if appliances == "end":
				continue
			#CheckIfDevice is in Whitelist ... 
			#if CheckWhitelist(appliances.get('serial')) == False:
			#	continue
			IsApplianceUp=DeviceUp(appliances.get('uplinks'),appliances.get('serial'),Orgs.get('name'), Orgs.get('id'))
			if IsApplianceUp == True:
				continue
			for interfaces in appliances.get('uplinks'):
				LoggingAddUplinks(appliances.get('serial'),interfaces.get('interface'), interfaces.get('status'), Orgs.get('name'), Orgs.get('id'))
##############################################################################################
# End of Functions
##############################################################################################