
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
	LoggingPrint()
	ReportTitle="Meraki CMDB report - "
	Logging2CSVandXLS(ReportTitle)
	sys.exit()		
#############################################################
#Find a specified org if needed
if args.search != None:
	results = FindOrgAndList(OrgResponse, args.search)
	if results == True:
		LoggingPrint()
	if results != True:
		print("No orgs found with this search criteria (check it has API access enabled)")
	sys.exit()		
#############################################################
#Delete this org
if (args.remove) != None:
	RWmode=True	
	DeleteOrg(args.remove,OrgResponse)
	ReportTitle="Meraki deleted org - " + str(args.remove)
	LoggingPrint()
	Logging2CSVandXLS(ReportTitle)
#############################################################
#Run Compliance report
if (args.review) == True:
	runningxxx(1, OrgResponse) #Show program is running.
	BigLoop(False, OrgResponse, 1)
	ReportTitle="Meraki Compliance Report" 
	LoggingPrint()
	Logging2CSVandXLS(ReportTitle)
#############################################################
#Run fix on an org
if (args.fix) != None:
	BigLoop(True, OrgResponse, args.fix)
	ReportTitle="Meraki Fix Report" 
	LoggingPrint()
	Logging2CSVandXLS(ReportTitle)	
#############################################################
#Run Up report
if (args.up) == True:
	runningxxx(1, OrgResponse) #Show program is running.
	print("here")
	CheckUP(OrgResponse)
	ReportTitle="Meraki Up-Down Report" 
	LoggingUplinkPrint()
	#Logging2CSVandXLS(ReportTitle)
#############################################################
#Run Compliance report
if (args.down) == True:
	runningxxx(1, OrgResponse) #Show program is running.
	CheckDeviceDown(OrgResponse)
	ReportTitle="Meraki Device Report" 
	LoggingPrint()
	Logging2CSVandXLS(ReportTitle)
#############################################################
