#------------------------------------
#--------import error check----------
import os
import shutil
import json
from time import sleep
from support.pull_files import pull_files
from support.json2yara import json2yara
from support.yara2json import yara2json

error_list = []
try:
	import yara
except ImportError:
	error_list.append('Error on import yara: goto yara.readthedocs.io for installation instructions')
if error_list:
	print '\n'.join(error_list)
	exit()
#--------import error check----------
#------------------------------------

process_path = 'Algoyara/00_processing'
finished_path = 'Algoyara/01_finished'
yararules_path = 'Algoyara/yararules'
ini_YARA_path = 'Algoyara/iniTEST.yar'
rule_map_path = 'Algoyara/rulemap.json'

def next_runs(rulemap, matches):
	matches_str = []
	for m in matches:
		matches_str.append(m.__str__())
	rules2run = []
	for rule in rulemap['rulemap']:
		if str(rule['rule']) in matches_str:
			new_rules = [str(run) for run in rule['run'] if str(run) not in rules2run]
			rules2run.extend(new_rules)
	return rules2run

def yara_callback(data):
	#pprint(data)
	return yara.CALLBACK_CONTINUE
	
def run_yara(yararules, f, yara_json, rulemap):
	yarac = yara.compile(source=yararules)
	matches = yarac.match(f, callback=yara_callback)
	if matches: 
		rules2run = next_runs(rulemap, matches)
		new_yara = json2yara(yara_json, rules2run)
		if new_yara:
			matches.extend(run_yara(new_yara, f, yara_json, rulemap))
		else:
			pass
	else:
		matches = []
	
	return matches

def main():
	
	#import 1st round of yara rules
	with open(ini_YARA_path, 'r') as f:
		yararules_ini = f.read()
	f.close()
	
	#import rulemap
	with open(rule_map_path, 'r') as f:
		rulemap = json.load(f)
	f.close()

	#import supporting yararules from folder
	yara_json = yara2json(yararules_path)
	
	while True:
		#pull files from processing folder
		process_list = pull_files(process_path)
		
		if not process_list:
			sleep(1) #check for files every second
		else:
			#pull files from finished folder
			finished_list = pull_files(finished_path)
			if finished_list:
				#checking for already processed files
				finished_names = [os.path.basename(path) for path in finished_list]
				for i in reversed(range(len(process_list))):
					if os.path.basename(process_list[i]) in finished_names:
						os.remove(process_list[i])	#remove already processed files from directory
						del process_list[i]
			for f in process_list:
				#run the recursive yara check
				matches = run_yara(yararules_ini, f, yara_json, rulemap)
				if matches:
					print '%s matched on %s' % (matches, os.path.basename(f))
				else:
					print 'no matches on %s' % os.path.basename(f)
				shutil.move(f, os.path.abspath(finished_path))
			sleep(1)

if __name__ == "__main__":
	main()
