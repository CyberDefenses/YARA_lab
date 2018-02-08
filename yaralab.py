import subprocess
from time import sleep

def main():
	cmd = ['python', 'Algoyara/Algorithmic-Yara.py']
	child = subprocess.Popen(cmd)

	print 'Running Yara Lab... type "quit" to terminate'
	
	while True:
		terminate = raw_input('').lower()
		if terminate == 'quit':
			child.terminate()
			print 'Yara Lab terminated'
			break
		else:
			print "invalid input"

if __name__ == "__main__":
	main()
