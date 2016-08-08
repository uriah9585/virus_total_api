#!/usr/bin/python

"""
Author: uriar
Version: 1.0
Summary: Queries Virus Total for all reports of the hashes provided.
priority:

	1.BitDefender
	2.Kaspersky
	3.Webroot
	4.McAfee
	5.ESET
	6.other

"""
import json
import urllib
import urllib2
import argparse
import os
import time
import hashlib
import Queue


# The Anti virus priority 
anti_virus_priority = {

	u'BitDefender' 	: 1,
	u'Kaspersky'	: 2,
	u'Webroot'		: 3,
	u'McAfee' 		: 4,
	u'Avast'		: 5,
	u'ESET'			: 6,
	u'Ad-Aware'		: 7,
	u'other'		: 8 


	
}


class Virus_total():

	def __init__(self,api_key):
		
		self.__key = api_key
		self.url = 'https://www.virustotal.com/vtapi/v2/'


	@property
	def key(self):
	    return self.__key
	

	def get_hash_report(self,hash):

		parameters = {"resource": hash,"apikey": self.__key}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(self.url + 'file/report', data)
		response = urllib2.urlopen(req)
		parse_json = json.loads(response.read())
		return parse_json

	@classmethod
	def verify_key(cls,key):
		try:
			if len(key) == 64:
				return key
			else:
				print "[ERROR] The key is not 64 characters."
				exit()
		except Exception as e:
			print str(e)

	@classmethod
	def verify_hash(cls,hash):
		try:
			if len(hash) == 32:
				return hash
			elif len(hash) == 40:
				return hash
			elif len(hash) == 64:
				return hash			
			else:
				print "[ERROR] the hash input is not valid."
				exit()	

		except Exception as e:
			print str(e)



def get_priority_hash(json_data):
	
	anti_virus = json_data['scans'].keys()
	
	if 'BitDefender' in anti_virus:
		return anti_virus_priority['BitDefender']
	elif 'Kaspersky' in anti_virus:
		return anti_virus_priority['Kaspersky']
	elif 'Webroot' in anti_virus:
		return anti_virus_priority['Webroot']
	elif 'McAfee' in anti_virus:
		return anti_virus_priority['McAfee']				
	elif 'Avast' in anti_virus:
		return anti_virus_priority['Avast']
	elif 'ESET' in anti_virus:
		return anti_virus_priority['ESET']
	elif 'Ad-Aware' in anti_virus:
		return anti_virus_priority['Ad-Aware']
	else: 
		return anti_virus_priority['other']						



def parser_data(json_data,output,priority,q_priority):

	if json_data['response_code'] == 0:
		q_priority.put((10,'HASH - %s - is not in virus total.' % json_data['resource']))
	elif json_data['response_code'] == 1:
		
		positives = int(json_data['positives'])	
		if not positives:
			q_priority.put((9,'HASH - %s - is not malicious.' % json_data['resource']))		
		else:
			q_priority.put((priority,'HASH - %s - is malicious. count:%s' % (json_data['resource'],json_data['positives'])))


def file_exists(filepath):
	try:
		if os.path.isfile(filepath):
			return filepath
		else:
			print "There is no file at:" + filepath
			exit()
	except Exception as e:
		print str(e)

def set_to_file(file_name,q_priority):
	file = open(file_name,'w+')
	file.write('Below is the identified malicious file.\n\n')
	while not q_priority.empty():
	    hash_to_write = q_priority.get()[1]
	    file.write(hash_to_write)
	    file.write('\n')
	file.close()


def main():
	parser = argparse.ArgumentParser(description="Query hashes against Virus Total.")
	parser.add_argument('-i', '--input', type=file_exists, required=False, help='Input File Location EX: /Somewhere/input.txt')
	parser.add_argument('-o', '--output', required=True, help='Output File Location EX: /Somewhere/output.txt ')
	parser.add_argument('-H', '--hash', type=Virus_total.verify_hash, required=False, help='Single Hash EX: d41d8cd98f00b204e9800998ecf8427e')
	parser.add_argument('-k', '--key', type=Virus_total.verify_key, required=True, help='API Key EX: ASDFADSFDSFASDFADSFDSFADSF')
	parser.add_argument('-u', '--unlimited', dest='unlimited', action='store_const', const=1, required=False, help='Changes the 26 second sleep timer to 1.')
	args = parser.parse_args()
	q_priority = Queue.PriorityQueue()
	
	#Run for a single hash + key
	if args.hash and args.key:
		vt = Virus_total(args.key)
		data = vt.get_hash_report(args.hash)
		if data:
			priority = get_priority_hash(data)
			parser_data(data,args.output,priority,q_priority)

	#Run for an input file + key
	elif args.input and args.key:
		vt = Virus_total(args.key)
		with open(args.input) as input_file:
			read_lines = input_file.readlines()
			for hash in read_lines:
				data = vt.get_hash_report(hash.rstrip())
				if data:
					priority = get_priority_hash(data)
					parser_data(data,args.output,priority,q_priority)
					
				if hash != read_lines[-1]:
					if args.unlimited == 1:
						time.sleep(1)
					else:
						time.sleep(26)

	set_to_file(args.output,q_priority)

# execute the program
if __name__ == '__main__':
	main()