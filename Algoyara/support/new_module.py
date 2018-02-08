import sys
import yara

def test_c(yarafile):
	try:
		yarac = yara.compile(yarafile)
		return yarac
	except yara.SyntaxError, why:
		print 'Compile Error: %s' % str(why)
		quit()
		
def main():
	module_name = sys.argv[1]
	yarafile = sys.argv[2]
	save_folder = 'modules'

	yarac = test_c(yarafile)
	yarac.save('%s/%s' % (save_folder, module_name))	

if __name__ == "__main__":
	main()
