#parses yarafile or directory and saves into json file

import json
import os
import sys
from pprint import pprint
from pull_files import pull_files
from parse_yara import parse_yara

def yara2json(yara_path):
	yarafiles = pull_files(yara_path, '.yar')
	data = {
			'rulename': [],
			'imports': [],
			'global': [],
			'private': [],
			'tags': [],
			'metadata': [],
			'strings': [],
			'condition': []
		}
	for yarafile in yarafiles:
		with open(yarafile, 'r') as f:
			yaratext = f.read()
		f.close()
		
		#print yarafile
		p_yara = parse_yara(yaratext)
		data['rulename'].extend(p_yara.rules['rulename'])
		data['imports'].extend(p_yara.rules['imports'])
		data['global'].extend(p_yara.rules['global'])
		data['private'].extend(p_yara.rules['private'])
		data['tags'].extend(p_yara.rules['tags'])
		data['metadata'].extend(p_yara.rules['metadata'])
		data['strings'].extend(p_yara.rules['strings'])
		data['condition'].extend(p_yara.rules['condition'])

	json_data = json.dumps(data)

	return json_data

def main():
	return yara2json(sys.argv[1])
	
if __name__ == "__main__":
	main()
