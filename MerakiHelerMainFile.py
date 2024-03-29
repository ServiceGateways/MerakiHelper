
#############################################################
#Start of script
#############################################################
if __name__ == '__main__':
	# Parse the arguments
	args = parseArguments()
#############################################################
#Sort out API keys
dashboard = ReadyAPIinterface(GetAPIKey())
#############################################################
#Get orgs
OrgResponse=GetOrgs(dashboard)
#############################################################
#List org access if needed
if args.list == True:
	runningxxx(1, OrgResponse) #Show program is running.
	ListOrgAccess(OrgResponse)
	
	ReportTitle="Meraki CMDB report - "
	Comment = "simple list of orgs which this API has access."
	LoggingPrint(ReportTitle, Comment)
	Logging2CSVandXLS(ReportTitle)
	sys.exit()		
#############################################################
#List org access if needed
if args.lic == True:
	runningxxx(1, OrgResponse) #Show program is running.
	GetTheLics(OrgResponse)
	ReportTitle="Meraki lic report - "
	Comment = "simple list of lics which this API has access."
	LoggingPrint(ReportTitle, Comment)
	Logging2CSVandXLS(ReportTitle)
	sys.exit()		
##############################################################
#Find a specified org if needed
if args.search != None:
	results = FindOrgAndList(OrgResponse, args.search)
	if results == True:
		ReportTitle = "Search"
		Comment = ""
		LoggingPrint(ReportTitle, Comment)
	if results != True:
		print("No orgs found with this search criteria (check it has API access enabled)")
	sys.exit()		
#############################################################
#Delete this org
if (args.remove) != None:
	RWmode=True	
	DeleteOrg(args.remove,OrgResponse)
	Comment = ""
	ReportTitle="Meraki deleted org - " + str(args.remove)
	LoggingPrint(ReportTitle, Comment)
	Logging2CSVandXLS(ReportTitle)
#############################################################
#Run Compliance report
if (args.review) == True:
	runningxxx(1, OrgResponse) #Show program is running.
	BigLoop(False, OrgResponse, 1)
	Comment = ""
	ReportTitle="Meraki Compliance Report" 
	LoggingPrint(ReportTitle, Comment)
	Logging2CSVandXLS(ReportTitle)
#############################################################
#Run fix on an org
if (args.fix) != None:
	BigLoop(True, OrgResponse, args.fix)
	Comment = ""
	ReportTitle="Meraki Fix Report" 
	LoggingPrint(ReportTitle, Comment)
	Logging2CSVandXLS(ReportTitle)	
#############################################################
#Run interface report up/down
if (args.int) == True:
	runningxxx(1, OrgResponse) #Show program is running.
	CheckUP(OrgResponse)
	ReportTitle="Meraki Interface up-down Report" 
	Comment = " API used = GET /organizations/{organizationId}/uplinks/statuses. Filtered devices with no issues"
	LoggingUplinkPrint(ReportTitle, Comment)
	Logging2CSVandXLS(ReportTitle)
#############################################################
#Run interface report loss
if (args.loss) == True:
	runningxxx(1, OrgResponse) #Show program is running.
	CheckLoss(OrgResponse)
	ReportTitle="Meraki Interface Loss Report" 
	Comment = " API used = GET /organizations/{organizationId}/devices/uplinksLossAndLatency"
	LoggingUplinkPrint(ReportTitle, Comment)
	Logging2CSVandXLS(ReportTitle)
##########################################################################################################################
#Run Device Down report
if (args.down) == True:
	runningxxx(1, OrgResponse) #Show program is running.
	CheckDeviceDown(OrgResponse)
	ReportTitle="Meraki Device Down Report" 
	Comment = "API used = GET /organizations/{organizationId}/devices/statuses. Filtered devices with no issues"
	LoggingPrint(ReportTitle, Comment)
	Logging2CSVandXLS(ReportTitle)
#############################################################
