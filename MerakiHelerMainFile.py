
#############################################################
#Start of script
#############################################################
if __name__ == '__main__':
	# Parse the arguments
	args = parseArguments()
# If running in rm mode, then only looking for one org
if (args.remove) != None:
	LoggingAdd("--WARNING-- Running in delete mode --WARNING-- ", "Ok", "Unknown",args.remove)
	Org_url = API_URLPrefix+str(args.remove)
	OrgResponse = GetOrgsToDelete(Org_url,args.remove)
	RWmode=True	
	print("--WARNING-- Running in delete mode --WARNING-- ")	
#############################################################
#Sort out API keys
headers = GetHeaders()
#############################################################
#Get orgs
OrgResponse=GetOrgs(headers)
runningxxx(1, OrgResponse) #Show program is running.
#############################################################
#List org access if needed
if args.list == True:
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
#Safety check, delete org only works with one org at a time
if len((OrgResponse)) > 2 and (args.remove) != None:
	print("Working with too many orgs... safety abort. Orgs listed =",len(OrgResponse))
	sys.exit()		
#############################################################
#Delete this org
if (args.remove) != None:
	DeleteOrg(args.remove,OrgResponse,headers)
	ReportTitle="Meraki deleted org - " + args.remove
	LoggingPrint()
	Logging2CSVandXLS(ReportTitle)
#############################################################
#Run Compliance report
if (args.review) == True:
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
	print("here")
	CheckUP(OrgResponse,headers)
	ReportTitle="Meraki Up-Down Report" 
	LoggingUplinkPrint()
	#Logging2CSVandXLS(ReportTitle)
	
