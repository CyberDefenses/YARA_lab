import re
import yara

class yaraparse():
	@staticmethod
	def compile_check(text):
		try:
			yara.compile(source=text)
			return True, None
		except yara.SyntaxError, why:
			return False, why

	def __init__(self, text):
		valid, why = yaraparse.compile_check(text)
		if valid:
			self.text = text
		else:
			print 'Compile Error: %s' % str(why)
			self.__del__()

		self.comments = []
		self.imports = []
		self.rules = {
				'rulename': [],
				'imports': [],
				'global': [],
				'private': [],
				'tags': [],
				'metadata': [],
				'strings': [],
				'condition': []
			}

	def scrub(self):
		#find, record, and remove all comment and import statements
		re_comment = re.compile(r'(?:\".*?\"|\'.*?\')|(/\*.*?\*/|//[^\r\n]*$)', re.MULTILINE|re.DOTALL)
		re_import = re.compile(r'\W*?(import\s*\"[a-zA-Z]*\")')
		comments = []
		imports = []

		matches = [n for n in re_comment.finditer(self.text)]
		for match in matches:
			if match.group(1):
				comments.append((match.span(1), match.group(1)))
				self.text = self.text.replace(match.group(1), '')
		self.comments = comments

		matches = re_import.findall(self.text)
		for match in matches:
			imports.append(match.split('"')[1])
			self.text = self.text.replace(match, '')
		self.imports = imports

		return None

	def parse(self):
		re_rule = re.compile(r'(?:\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(?:\/(?:\\.|[^\/\\])*\/)|(global|private|rule.*?{)|(meta\s*:)|(strings\s*:)|(condition\s*:)', re.DOTALL | re.MULTILINE)
		re_meta = re.compile(r'(\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(\w*\s*=)|(true|false)|([0-9])', re.DOTALL)
		re_string = re.compile(r'(\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(nocase|fullword|ascii|wide)|({[A-Fa-f0-9\(\)\?\s\|\[\]\-]*})|(\/.*?\/)|(\$\w*\s*=\s*)', re.DOTALL)
		match = [n for n in re_rule.finditer(self.text)]

		# parse out global, private, rulename, tags, meta, strings, conditions
		rules = []
		meta = []
		string = []
		condition = []
		G = False # Global
		P = False # Private
		for i in range(len(match)):
			if match[i].group(1): # global, private, rulename, tags
				if match[i].group(1) == 'global':
					G = True
				elif match[i].group(1) == 'private':
					P = True
				else:
					rule_split = match[i].group(1).split(':')
					if len(rule_split) > 1:
						tags = rule_split[-1].replace('{', '').split()
					else:
						tags = []
					rulename = rule_split[0].replace('{', '').split()[-1]

			if match[i].group(2): # meta
				start_index = match[i].end(2)
				n = 1
				try:
					while not(match[i+n].group(3) or match[i+n].group(4)):
						n += 1
					end_index = match[i+n].start(0)
					meta_matches = [n for n in re_meta.finditer(self.text, start_index, end_index)]

					for meta_match in meta_matches:
						if meta_match.group(2):
							meta_name = meta_match.group(2).replace('=', '').rstrip()
						else:
							meta_content = meta_match.group(0)
							meta.append({'name': meta_name, 'content': meta_content})

				except IndexError:
					continue

			if match[i].group(3): # strings
				start_index = match[i].end(3)
				n = 1
				try:
					while not(match[i+n].group(4)):
						n += 1
					end_index = match[i+n].start(0)
					string_match = [n for n in re_string.finditer(self.text, start_index, end_index)]

					for ii in range(len(string_match)):
						modifiers = []
						if string_match[ii].group(5): # name
							string_name = string_match[ii].group(5).replace('=', '').rstrip()
						elif string_match[ii].group(1): # text string
							string_type = 'text'
							string_content = string_match[ii].group(1)
							m = 1
							while string_match[ii+m].group(2):
								modifiers.append(string_match[ii+m].group(2))
								m += 1
								if (ii+m) >= len(string_match):
									break
							string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
						elif string_match[ii].group(3): # hex string
							string_type = 'hex'
							string_content = string_match[ii].group(3)
							string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
						elif string_match[ii].group(4): # regex string
							string_type = 'regex'
							string_content = string_match[ii].group(4)
							string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})

				except IndexError:
					string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
					continue

			if match[i].group(4): # condition
				start_index = match[i].end(4)
				n = 1
				try:
					while not(match[i+n].group(1)):
						n += 1
					end_index = match[i+n].start(0)
					condition = self.text[start_index:end_index].replace('}', '').strip()

				except IndexError:
					condition = self.text[start_index:].replace('}', '').strip()

				self.rules['rulename'].append(rulename)
				self.rules['imports'].append([imp for imp in self.imports if imp+'.' in condition])
				self.rules['global'].append(G)
				self.rules['private'].append(P)
				self.rules['tags'].append(tags)
				self.rules['metadata'].append(meta)
				self.rules['strings'].append(string)
				self.rules['condition'].append(condition)

				G = False
				P = False
				meta = []
				string = []

		return None

def parse_yara(text):
	p_yara = yaraparse(text)
	p_yara.scrub()
	p_yara.parse()
	return p_yara

def main():
	yarafile = sys.argv[1]
	with open(yarafile, 'r') as f:
			yaratext = f.read()
	f.close()
	return parse_yara(yaratext)

if __name__ == "__main__":
	main()
