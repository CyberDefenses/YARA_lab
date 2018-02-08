#takes json organized yara and outputs a yara file

import json
import sys
import os

def pull_rules(data, rules):
	if rules:
		new_data = {
			'rulename': [],
			'imports': [],
			'global': [],
			'private': [],
			'tags': [],
			'metadata': [],
			'strings': [],
			'condition': []
		}
		
		if not(type(rules) == list):
			rules = [rules]
			
		indexes = []
		for rule in rules:
			try:
				indexes.append(data['rulename'].index(rule))
			except ValueError:
				pass
		
		for index in indexes:
			new_data['rulename'].append(data['rulename'][index])
			new_data['imports'].append(data['imports'][index])
			new_data['global'].append(data['global'][index])
			new_data['private'].append(data['private'][index])
			new_data['tags'].append(data['tags'][index])
			new_data['metadata'].append(data['metadata'][index])
			new_data['strings'].append(data['strings'][index])
			new_data['condition'].append(data['condition'][index])
		return new_data
	else:
		return None

def json2yara(json_obj, rules=[]):
	
	data = json.loads(json_obj)
	data = pull_rules(data, rules)
	
	rules = []
	all_imports = []
	
	if data:
		for i in range(len(data['rulename'])):
			rulename = data['rulename'][i]
			imports = data['imports'][i]
			glob = data['global'][i]
			private = data['private'][i]
			tags = data['tags'][i]
			metadata = [(meta['name'], meta['content']) for meta in data['metadata'][i]]
			strings = [(string['name'], string['string'], string['modifiers']) for string in data['strings'][i]]
			condition = data['condition'][i]

			yararule = []
			if imports:
				for imp in imports:
					if imp in all_imports:
						pass
					else:
						all_imports.append(imp)

			if glob:
				yararule.append('global ')
			
			if private:
				yararule.append('private ')

			yararule.append('rule %s' % rulename)

			if tags:
				yararule.append(': %s' % ' '.join(tags))

			yararule.append('\n{\n')

			if metadata:
				yararule.append('\tmeta:\n')
				for meta in metadata:
					yararule.append('\t\t%s = %s\n' % (meta[0], meta[1]))
			
			if strings:
				yararule.append('\tstrings:\n')
				for string in strings:
					yararule.append('\t\t%s = %s' % (string[0], string[1]))
					if string[2]:
						yararule.append(' %s' % ' '.join(string[2]))
					yararule.append('\n')
			
			yararule.append('\tcondition:\n\t\t%s\n}\n\n' % condition)
			
			rules.extend(yararule)

		return '\n'.join(all_imports) + ''.join(rules)
	else:
		return None

def main():
	return json2yara(sys.argv[1])

if __name__ == "__main__":
	main()
