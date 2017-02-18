##############################################################################
#Malicious Domain search script written by Erik Iker
#Python Script to parse internet history from Netanalysis in csv format and 
#refine the history looking for high risk items to be malicious domains based
#on domain name length of total amount of digits in the domain name
#will add proximity of multiple vowels in a later version
#############################################################################
import os 
import re
import codecs
import datetime
print ("\n\nMalicious Domain Search Tool written by Erik Iker\nA tool to search Netanalysis output for high risk URLs consistent with those generated for malware campaigns")
print ("Please provide any feedback for improvement to @ErikIkerFW\n") 
print ("Based upon high number of characters in domain name, the URI string ending with 'exe',certain high risk country codes for the top level domain\
	high amount of digits in a domain name, or higher than normal pattern of rare characters in the URL.\n")
print ("###############################################################################\n\
# All Logs must to be parsed must have a CSV extension and be in csv format   #\n\
# There is error handling for proxy logs that happen to be space delimited    #\n\
# All log files to be even space demlimited proxy must have a csv extension   #\n\
# Analyst must not introduce any other delimiter through manipulating logs    #\n\
###############################################################################\n\n")
###################
#global variables
###################
#this is a regular expression for numbers to look for in URLs, this regex will be called in the processing function to conduct searches
digits = re.compile("[0-9]")
#rareChar is a regular expression to find characters that are used with less frequency in normal English words than other characters.  
#The total amount of times these characters appear will be pulled from a URL and weighted against the total charater count for the URL to make a 
#determnination of whether that URL may appear more likely to be jibberish than to be words normally in speech. based upon character frequency of speech in Cornell study + digits
rareChar = re.compile('[zqjvxky0-9]')
#expression to strip all dots and hyphens from a URL address for comparing against the rareChar for scoring.  Amount of dots for subdomains made unpredicatable results
alphaNumeric = re.compile('[a-zA-Z0-9]')
validTypes = re.compile('[1234]')
#regex to search for vowels, used in processing methods
vowels = re.compile('[aeiou]')
#regex to look for characters generally found in the parameters passed in a URL after the top level domain.
#This is necessary to help eliminate these fields which can break the parsing mechanisms of this script
parameters = re.compile('[=/%]')
#comment
urlmatch = re.compile('h?h?t?tps?://[\-\._:~a-zA-Z0-9]+/?')
#List of data types found in the first column of netanalysis input which will be tested for
#Only rows that have one of the strings in the validLines list will be processed further. 
#Any additional types desired for processing will need to be added here
validLines = ["hhttp", "http", "https", "redirect", "cache", "privacie", "feed", "History", "Redirect", "Download", "TopSites", "Cache"]
#get today's date and time to stamp in file names to reduce old output from being overwritten if several files in the same path will be processed in one day 
time = datetime.datetime.now().strftime("%Y%m%d-%H%M")
#sometimes used to count lines for troubleshooting
skip = 0
#Friendly company names to exclude from processing and consideration
friendlyDomains = ["cisco.com"]
#List of Top Level Domains that are high risk for malicious content
highRiskTLD = ["cn", "ru", "in", "pl", "cz", "su", "vn", "cm", "am", "pw", "so", "to"]
#############################
#method definitions
#############################

#This method gets input from the user for the directory where their input logs are stored and checks to make sure that is a valid path before processing continues
def get_path():
	input_path = raw_input ('Enter the path of Netanalysis, proxy logs, or Log2Timeline bodyfile in csv format you wish to search: ')
	path = os.path.normpath(input_path)
	while os.path.isdir(input_path) != True:
		input_path = raw_input ('Enter the path of the logs:')
		path = os.path.normpath(input_path)
		if os.path.isdir(input_path) != True:
			print ('That path does not exist. \n')
	return path

#The get_type method presents a menu to the user for them to select a digit for which type of logs they have and the stringency of search results they want returned
#It should only continue if a valid number between 1 and 4 is selected and then pass that number on for processing.  Right now the error checking is not working, but the user is shown the number they selected
def get_type():
	print ("\n\n\nSelect the type of logs for your input and determine the restrictiveness of the seach by choosing one of the following options and hitting enter\n")
	print ("Second Level Domain options will limit the search for patterns association with malicious domains to only the second level domain (the last domain name before .com, .net etc)\n")
	print ("All domains search options will check all domains and subdomains in an address.  It will result in many more false positives")
	print ("Current Version will not parse Log2Timeline files in the Excel ('xlsx') template. It will only work on the plain text bodyfile format in a ('csv') file")
	inputType = 0
	while (re.match(validTypes, str(inputType)) != True):
		inputType = raw_input("\n1.Netanalysis 'All Domains' search:\n\n2.Netanalysis 'Second Level Domain' search\n\n3.Bluecoat 'All Domains' search\n\n4.Bluecoat 'Second Level Domain' search\n\n5.Log2Timeline Bodyfile 'All Domains' search\n\n6.Log2Timeline Bodyfile 'Second Level Domain' search\n\n Enter only the number for the type of search you wish to run:")
		print ("Input Type selected is: " + inputType)
		#if (inputType == 'p' or inputType == 'n'):
		return inputType

#method to process proxy logs to search each domain and subdomain for the DGA variables prescribed
def proxyAllDomains(path):
	#makes a variable for the first line in the file so that the header of the row will not cause an error and can be written to the output
	# the method for this now will write a header for each input file, and I may make an if loop later to only use this variable and the write from it once if it is problematic
	headerLine = next(procfile)
	resultsfile.write(headerLine)
	firstLine = procfile.readline();
	comma = firstLine.count(',')
	space = firstLine.count(' ')
	for line in procfile:
		#test to see if proxy logs are comma or space delimited and perform the slit accordingly
		if (comma > 0):
			address = line.split(',')[10]
		elif (space > 0):
			address = line.split(' ')[10]
		else:
			print ("The delimiter for your proxy logs is irregular and not being handled properly by this script")
			break
		#each line is read and then at the 11th row the data is split out for processing.  That's where the URL domain info is
		address = line.split(',')[10]
		#count the number of dots (.) in the domain list so that we can stop processing without errors and have an incrementer to process each domain separately
		count = address.count('.')
		#determine if high risk top level domains are being navigated to and if so, write that line out for review.  This may need to be commented out for 
		#investigations of computers in non-US countries
		TopLevelDomain = address.split('.')[count]
		TLD = ''.join(TopLevelDomain)
		TLD.strip()
		if any(s in TLD for s in highRiskTLD):
			resultsfile.write(line)
			continue
		#Check to see if the URL address is for the company name of domain being investigated and pass on it if condition matches
		if any(s in address for s in friendlyDomains):
			continue
		# determine the amount of rare characters in the URL and determine if more than a third of the characters in the URL is composed of these
		normalized = re.findall(alphaNumeric, address)
		rarecount = re.findall(rareChar, address)
		if (len(rarecount) > len(normalized)/3):
			resultsfile.write(line)
			continue
		#initialize size to one to try to skip the .com and beyond in later subscripts
		size = 1
		#from zero and for as many dots as were determined process the data
		for x in range(0, (count)):
			while (size <= count):
				#split to each domain and subdomain as the for loop iterates
				domainList = address.split('.')[size-1:size]
				#domainList from the split is considered a list, so it has to be joined to make it a string for further processing
				domain = ''.join(domainList)
				#strip the whitespace from each side of the string
				domain.strip()
				#increment the size so we can process the next domain or subdomain 
				size = size + 1
				#if the domain is not over or equal to 20 characters test it to see if it has more than three digits in
				#a domain name, if it does, write that line out as a probable DGA URL
				if (len(domain) > 20):
					resultsfile.write(line)
					break
				if (len(domain) <= 20):
					# look for the amount of digits in the domain name and if there are more than 3, write that line to the file
					numbers = re.findall(digits, domain)
					if (len(numbers) > 3):
						resultsfile.write(line)
						break

				#if none of the DGA indicators being considered are found then the script moves on to the next domain/subdomain in the line
				else: continue	

def proxy2LD(path):
	headerLine = next(procfile)
	resultsfile.write(headerLine)
	firstLine = procfile.readline();
	comma = firstLine.count(',')
	space = firstLine.count(' ')
	for line in procfile:
		#split to the 11th column of proxy logs where the URL domain is
		if (comma > 0):
			address = line.split(',')[10]
		elif (space > 0):
			address = line.split(' ')[10]
		else:
			print ("The delimiter for your proxy logs is irregular and not being handled properly by this script")
			break
		#count the number of dots in the domain name
		count = address.count('.')
		#determine if high risk top level domains are being navigated to and if so, write that line out for review.  This may need to be commented out for 
		#investigations of computers in non-US countries
		TopLevelDomain = address.split('.')[count]
		TLD = ''.join(TopLevelDomain)
		TLD.strip()
		if any(s in TLD for s in highRiskTLD):
			resultsfile.write(line)
			continue
		#Check to see if the URL address is for the company name of domain being investigated and pass on it if condition matches
		if any(s in address for s in friendlyDomains):
			continue
		#back out one from the last dot to get the domain name just before the TLD, and do further processing on that 2nd level domain only
		domainList = address.split('.')[count - 1] 
		domain = ''.join(domainList)
		domain.strip()
		#look for rarecharacters in the second level domain and if more than a third the total length of the domain is digits, vowels and other characters from the rareChar expression, write the line
		rarecount = re.findall(rareChar, domain)
		if (len(rarecount) > len(domain)/3):
			resultsfile.write(line)
			continue
		if (len(domain) > 20):
			resultsfile.write(line)
			break
		if (len(domain) <= 20):
			# look for the amount of digits in the domain name and if there are more than 4, write that line to the file
			numbers = re.findall(digits, domain)
			if (len(numbers) > 3):
				resultsfile.write(line)
				break

		else:
			continue	

#method to do for process netanalysis logs in a way that each domain and subdomain are considered for the DGA criteria
def na2LD(path):
	skip=0
	#makes a variable for the first line in the file so that the header of the row will not cause an error and can be written to the output
	# the method for this now will write a header for each input file, and I may make an if loop later to only use this variable and the write from it once if it is problematic
	headerLine = next(procfile)
	resultsfile.write(headerLine)
	for line in procfile:
		skip = skip +1
		#split each line on the first field to see if the field is "FormHistory" which will break processing,
		#and then test to see that the field name is one of the whitelisted validLine types from the global variables a line should start with to be considered for processing
		lineType = line.split(',')[0]
		if ("FormHistory" in lineType):
			continue
		#checks to see if the line starts with any of the global variable "validLine" names
		if any(s in lineType for s in validLines):
			#second level of checking, sometimes Netanalysis csv files end up with broken output and have lines broken up over several rows
			#this can break processesing. A commonly complete row has 49 commas, so this will see if there is at least enough data to process and leaves a lot of slack
			validDetermine = line.count(',')
			#if there aren't enough commas in a row to consider for processing that line is written to the errors file for the examiner to review
			if (validDetermine < 30):
				errorsfile.write(line)
			#if there are enough commas, then processing continues
			else:
				#netanalysis files are comma separate and the 7th column is where the full URL is
				URL = line.split(',')[6]
				#If a URL ends with .exe it could be reviewed to determine what type of executable and other information are being delivered with the executable
				if URL.lower().endswith('.exe'):
					resultsfile.write(line)
					continue
				#regex to get all items
				addresses = re.findall(urlmatch, URL)
				address1 = ''.join(addresses)
				if ('://' in address1):
					address2 = address1.split('://')[1]
				elif ('://' not in address1):
					address2 = address1
				address = address2.split('/')[0]
				#determine if high risk top level domains are being navigated to and if so, write that line out for review.  This may need to be commented out for 
				#investigations of computers in non-US countries
				count = address.count('.')
				if (count >= 1):
					TopLevelDomain = address.split('.')[count]
					TLD = ''.join(TopLevelDomain)
					TLD.strip()
					if any(s in TLD for s in highRiskTLD):
						resultsfile.write(line)
						continue
					#Check to see if the URL address is for the company name of domain being investigated and pass on it if condition matches
					if any(s in address for s in friendlyDomains):
						continue
					#count the number of dots for domains to keep for loop from trying to run beyond the .com or other TLD
					containsParameters = re.findall('[%=/]', address)
					#print("line number " + str(skip))
					if (len(containsParameters) > 0):
						print("still has parameters in domain: ")
					#If there are no parameter-type symbols in the URL this processing decision structure takes over
					elif (len(containsParameters) ==0) :
						if (count >= 1):
							domainList = address.split('.')[count - 1] 
							domain = ''.join(domainList)
							domain.strip()
							#look for rarecharacters in the second level domain and if more than a third the total length of the domain is digits, vowels and other characters from the rareChar expression, write the line
							rarecount = re.findall(rareChar, domain)
							if (len(rarecount) > len(domain)/3):
								resultsfile.write(line)
								#print(str(skip) + "line added to results because of rarechar rule: " + domain)
								continue
							if (len(domain) > 20):
								resultsfile.write(line)
								#print(str(skip) + "line added to results because of length rule: " + domain)
								continue
							if (len(domain) <= 20):
								# look for the amount of digits in the domain name and if there are more than 4, write that line to the file
								numbers = re.findall(digits, domain)
								if (len(numbers) > 3):
									resultsfile.write(line)
									#print(str(skip) + "line added to results because of digits rule: " + domain)
									continue
							else: continue
						# if there are no dots in the address then it is probably a local resource and does not need to be processed
						else:
							errorsfile.write(line)
				#if there are no dots in the address then it is likely a local resource that does not need to be processed
				else:
					continue
		#if the line type is not included in those desired for processing, it will be passed, such as cookie or others not in validLines array
		else:
			continue
#The old logic for inclusive, should maybe be called exhaustive
def naAllDomains(path):
	skip =0
	#makes a variable for the first line in the file so that the header of the row will not cause an error and can be written to the output
	# the method for this now will write a header for each input file, and I may make an if loop later to only use this variable and the write from it once if it is problematic
	headerLine = next(procfile)
	resultsfile.write(headerLine)
	for line in procfile:
		skip = skip + 1
		#print "line number: " + str(skip)
		#split each line on the first field to see if the field is "FormHistory" which will break processing,
		#and then test to see that the field name is one of the whitelisted validLine types from the global variables a line should start with to be considered for processing
		lineType = line.split(',')[0]
		if ("FormHistory" in lineType):
			continue
		#checks to see if the line starts with any of the global variable "validLine" names
		if any(s in lineType for s in validLines):
			#second level of checking, sometimes Netanalysis csv files end up with broken output and have lines broken up over several rows
			#this can break processesing. A commonly complete row has 49 commas, so this will see if there is at least enough data to process and leaves a lot of slack
			validDetermine = line.count(',')
			#if there aren't enough commas in a row to consider for processing that line is written to the errors file for the examiner to review
			if (validDetermine < 30):
				errorsfile.write(line)
			#if there are enough commas, then processing continues
			else:
				#netanalysis files are comma separate and the 7th column is where the full URL is
				URL = line.split(',')[6]
				#If a URL ends with .exe it could be reviewed to determine what type of executable and other information are being delivered with the executable
				if URL.lower().endswith('.exe'):
					resultsfile.write(line)
					continue
				#count the number of dots for domains to keep for loop from trying to run beyond the .com or other TLD
				addresses = re.findall(urlmatch, URL)
				address1 = ''.join(addresses)
				if ('://' in address1):
					address2 = address1.split('://')[1]
					#print(':// address is ' + address2)
				elif ('://' not in address1):
					#print ("No :// address is " + address2)
					address2 = address1
				address = address2.split('/')[0]
				#determine if high risk top level domains are being navigated to and if so, write that line out for review.  This may need to be commented out for 
				#investigations of computers in non-US countries
				count = address.count('.')
				if (count >= 1):
					TopLevelDomain = address.split('.')[count]
					TLD = ''.join(TopLevelDomain)
					TLD.strip()
					if any(s in TLD for s in highRiskTLD):
						resultsfile.write(line)
						continue
					#Check to see if the URL address is for the company name of domain being investigated and pass on it if condition matches
					if any(s in address for s in friendlyDomains):
						continue
					# determine the amount of rare characters in the URL and determine if more than a third of the characters in the URL is composed of these
					# determine the amount of rare characters in the URL and determine if more than a third of the characters in the URL is composed of these
					if address.startswith('www.'):
						stripWWW = address.split('www.')[1]
						stripWWW1 = ''.join(stripWWW)
						stripWWW1.strip()
						stripTLD = stripWWW1('.')[1:count]
					elif address.startswith('www.') == False:
						stripTLD = address.split('.')[0:(count)]
					noTLD = ''.join(stripTLD)
					noTLD.strip()
					print noTLD
					normalized = re.findall(alphaNumeric, noTLD)
					rarecount = re.findall(rareChar, noTLD)
					if (len(rarecount) > len(normalized)/3):
						resultsfile.write(line)
						print(str(skip) + "line added to results because of rarechar rule: " + address)
						continue
					else:
						#initialize size to skip the .com and beyond in later subscripts and have an incrementer so that all domains/subdomains can be processed
						size = 0
						for x in range(0, (count)):
							#split to each domain and subdomain as the for loop iterates - this works the same as the proxy methods for incrementing and joining the list to a string for processing
							domainList = address.split('.')[size:size+1]
							domain = ''.join(domainList)
							domain.strip()
							size = size + 1
							#looks to see if any parameter items are in the domain name so that processing can skip anything that looks like a domain, but is in the passed parameters beyond the TLD
							parameter = re.findall(parameters, domain)
							if (len(parameter) == 0):
								#if the domain is not over or equal to 20 characters test it to see if it has more than three digits in
								#a domain name, if it does, write that line out as a probable DGA URL
								if (len(domain) > 20):
									resultsfile.write(line)
									print(str(skip) + "line added to results because of length rule: " + domain)
									break
								if (len(domain) <= 20):
									# look for the amount of digits in the domain name and if there are more than 4, write that line to the file
									numbers = re.findall(digits, domain)
									if (len(numbers) > 3):
										resultsfile.write(line)
										#print(str(skip) + "line added to results because of digits rule: " + domain)
										break
								#if none of the conditions for DGA are met then that line is skipped
								else:
									continue
							#if the item has parameter items in it then skip the item
							else:
								print ("There are parameters in the address" + domain)
				#if there are no dots then it is likely an internal resource that does not need to be processed
				else:
					#print ("dotless domain: " + address)
					continue
		#If none of the whitelisted "validLine" types from the global variable are found in the first row of the input then the script writes that line to the errors file	
		else:
			continue
def l2t2LD(path):
	skip=0
	#makes a variable for the first line in the file so that the header of the row will not cause an error and can be written to the output
	# the method for this now will write a header for each input file, and I may make an if loop later to only use this variable and the write from it once if it is problematic
	headerLine = next(procfile)
	resultsfile.write(headerLine)
	for line in procfile:
		skip = skip +1
		#print ("line number" + str(skip))
		#check to determine that the line contains valid data with enough fields to parse
		validDetermine = line.count(',')
		#if there aren't enough commas in a row to consider for processing that line is written to the errors file for the examiner to review
		if (validDetermine < 10):
			errorsfile.write(line)
		#if there are enough commas, then processing continues
		else:
			#split each line on the fourthfield to see if the field is "WEBHIST" to determine if that line will contain a URL
			lineType = line.split(',')[4]
			#print ("linetype field is: " + lineType)
			if ("WEBHIST" in lineType):
				#netanalysis files are comma separate and the 7th column is where the full URL is
				URL = line.split(',')[9]
				#If a URL ends with .exe it could be reviewed to determine what type of executable and other information are being delivered with the executable
				if URL.lower().endswith('.exe'):
					resultsfile.write(line)
					continue
				#regex to get all items
				addresses = re.findall(urlmatch, URL)
				address1 = ''.join(addresses)
				if ('://' in address1):
					address2 = address1.split('://')[1]
				elif ('://' not in address1):
					address2 = address1
				address = address2.split('/')[0]
				#determine if high risk top level domains are being navigated to and if so, write that line out for review.  This may need to be commented out for 
				#investigations of computers in non-US countries
				count = address.count('.')
				if (count >= 1):
					TopLevelDomain = address.split('.')[count]
					TLD = ''.join(TopLevelDomain)
					TLD.strip()
					if any(s in TLD for s in highRiskTLD):
						resultsfile.write(line)
						continue
					#Check to see if the URL address is for the company name of domain being investigated and pass on it if condition matches
					if any(s in address for s in friendlyDomains):
						continue
					#count the number of dots for domains to keep for loop from trying to run beyond the .com or other TLD
					containsParameters = re.findall('[%=/]', address)
					#print("line number " + str(skip))
					if (len(containsParameters) > 0):
						print("still has parameters in domain: ")
					#If there are no parameter-type symbols in the URL this processing decision structure takes over
					elif (len(containsParameters) ==0) :
						domainList = address.split('.')[count - 1] 
						domain = ''.join(domainList)
						domain.strip()
						#look for rarecharacters in the second level domain and if more than a third the total length of the domain is digits, vowels and other characters from the rareChar expression, write the line
						rarecount = re.findall(rareChar, domain)
						if (len(rarecount) > len(domain)/3):
							resultsfile.write(line)
							print(str(skip) + "line added to results because of rarechar rule: " + domain)
							continue
						#if the domain name is greater than 20 characters in length, write the line.  
						if (len(domain) > 20):
							resultsfile.write(line)
							print(str(skip) + "line added to results because of domainlength rule: " + domain)
							continue
						if (len(domain) <= 20):
							# look for the amount of digits in the domain name and if there are more than 4, write that line to the file
							numbers = re.findall('[0-9]', domain)
							if (len(numbers) > 3):
								resultsfile.write(line)
								print(str(skip) + "line added to results because of digit count rule: " + domain)
								continue
						else: continue
				#pass the line if there are no dots as it is likely and internal webapp
				else:
					continue
			#continue if the line type is not "WEBHIST" determined by the 4th column
			else:
				continue

def l2t2AllDomains(path):
	skip=0
	#makes a variable for the first line in the file so that the header of the row will not cause an error and can be written to the output
	# the method for this now will write a header for each input file, and I may make an if loop later to only use this variable and the write from it once if it is problematic
	headerLine = next(procfile)
	resultsfile.write(headerLine)
	for line in procfile:
		skip = skip +1
		#print ("line number" + str(skip))
		#check to determine that the line contains valid data with enough fields to parse
		validDetermine = line.count(',')
		#if there aren't enough commas in a row to consider for processing that line is written to the errors file for the examiner to review
		if (validDetermine < 10):
			errorsfile.write(line)
		#if there are enough commas, then processing continues
		else:
			#split each line on the fourthfield to see if the field is "WEBHIST" to determine if that line will contain a URL
			lineType = line.split(',')[4]
			#print ("linetype field is: " + lineType)
			if ("WEBHIST" in lineType):
				#netanalysis files are comma separate and the 7th column is where the full URL is
				URL = line.split(',')[9]
				#If a URL ends with .exe it could be reviewed to determine what type of executable and other information are being delivered with the executable
				if URL.lower().endswith('.exe'):
					resultsfile.write(line)
					continue
				addresses = re.findall(urlmatch, URL)
				address1 = ''.join(addresses)
				if ('://' in address1):
					address2 = address1.split('://')[1]
					#print(':// address is ' + address2)
				elif ('://' not in address1):
					#print ("No :// address is " + address2)
					address2 = address1
				address = address2.split('/')[0]
				#determine if high risk top level domains are being navigated to and if so, write that line out for review.  This may need to be commented out for 
				#investigations of computers in non-US countries
				count = address.count('.')
				if (count >= 1):
					TopLevelDomain = address.split('.')[count]
					TLD = ''.join(TopLevelDomain)
					TLD.strip()
					if any(s in TLD for s in highRiskTLD):
						resultsfile.write(line)
						continue
					#Check to see if the URL address is for the company name of domain being investigated and pass on it if condition matches
					if any(s in address for s in friendlyDomains):
						continue
					# determine the amount of rare characters in the URL and determine if more than a third of the characters in the URL is composed of these
					normalized = re.findall(alphaNumeric, address)
					rarecount = re.findall(rareChar, address)
					if (len(rarecount) > len(normalized)/3):
						resultsfile.write(line)
						print(str(skip) + "line added to results because of rarechar rule: " + line)
						continue
					#initialize size to skip the .com and beyond in later subscripts and have an incrementer so that all domains/subdomains can be processed
					size = 0
					for x in range(0, (count)):
						#split to each domain and subdomain as the for loop iterates - this works the same as the proxy methods for incrementing and joining the list to a string for processing
						domainList = address.split('.')[size:size+1]
						domain = ''.join(domainList)
						domain.strip()
						#print domain
						size = size + 1
						#looks to see if any parameter items are in the domain name so that processing can skip anything that looks like a domain, but is in the passed parameters beyond the TLD
						parameter = re.findall(parameters, domain)
						if (len(parameter) == 0):
							#if the domain is not over or equal to 20 characters test it to see if it has more than three digits in
							#a domain name, if it does, write that line out as a probable DGA URL
							if (len(domain) > 20):
								resultsfile.write(line)
								print(str(skip) + "line added to results because of domain length rule: " + domain )	

								continue
							if (len(domain) <= 20):
								# look for the amount of digits in the domain name and if there are more than 4, write that line to the file
								numbers = re.findall(digits, domain)
								if (len(numbers) > 3):
									resultsfile.write(line)
									print(str(skip) + "line added to results because of amount of digits rule: " + line)
									continue
							#if none of the conditions for DGA are met then that line is skipped
							else:
								continue
						#if the item has parameter items in it then skip the item
						else:
							continue
				#if there are no dots in the address do not process it as it is likely an internal resource and not being routed to an external domain
				else:
					continue
			#continue if the line type is not "WEBHIST" determined by the 4th column
			else:
				continue

##############################
####End of method Definitions
##############################
#main code and function calls
##############################								
path = get_path()
inputType = get_type()
#generate unique filename for each output and set it writable
result_file_name = ("High-Risk-Domain-History" + str(time) + ".xls")
results_file_name = os.path.normpath(path + "//" + result_file_name)
errors = os.path.normpath(path + "//" + str(time) + "processing-errors.log")

with codecs.open ((errors), encoding='utf-8', mode='w', errors='replace') as errorsfile:
	print("Lines that could not be processed are being written for review to " + errors)
	with codecs.open ((results_file_name), encoding='utf-8', mode='w', errors='replace') as resultsfile:
		print ("writing results to: " + str(results_file_name))
		for filename in os.listdir(path):
			if filename.lower().endswith('.csv'):
				print("processing: " + str(filename))
				with codecs.open(path + os.sep + filename, encoding='utf-8', errors='replace') as procfile:
					if inputType == '1':
						naAllDomains(path)
					if inputType == '2':
						na2LD(path)
					if inputType == '3':
						proxyAllDomains(path)
					if inputType == '4':
						proxy2LD(path)
					if inputType == '5':
						l2t2AllDomains(path)
					if inputType == '6':
						l2t2LD(path)
