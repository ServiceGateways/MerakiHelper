#############################################################
# This script assists with Meraki deployments for DIA 
# 
# 
# Execute with --help for assistance
#  
# CSV and XLS file is name will be 
# created at ......
#
# Created by Stuart Manderson - Product Architect for
# DIA Evolution NPD ... aka. Meraki
#
#
#############################################################
# Various libraries
#############################################################
import httpimport
url = "https://raw.githubusercontent.com/ServiceGateways/MerakiHelper/main/MerakiHelerSupportFile.py"
with httpimport.remote_repo(["MerakiHelerSupportFile"], url):
	from MerakiHelerSupportFile import *
	print("imported MerakiHelerSupportFile")
#############################################################
# Read in command line arguments and execute
#############################################################
import requests as req
resp = req.get("https://raw.githubusercontent.com/ServiceGateways/MerakiHelper/main/MerakiHelerMainFile.py")
exec(resp.text)
#############################################################

