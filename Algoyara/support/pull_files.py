import os
import sys

def listdir_nohidden(path):
	#list directory, excludes hidden files
    for f in os.listdir(path):
        if not f.startswith('.'):
            yield f

def pull_files(d, *args):
	#returns absolute path of all files (including subdirectories) in directory d
	 
	files = []
	for item in listdir_nohidden(d):
		path = os.path.join(d, item)
		if os.path.isfile(path):
			if args:
				extension = os.path.splitext(path)[1]
				if extension in args:
					files.append(os.path.abspath(path))
			else:
				files.append(os.path.abspath(path))
		else:
			files.extend(pull_files(path))
	return files

def main():
	return pull_files(sys.argv[1])
	
if __name__ == "__main__":
	main()
