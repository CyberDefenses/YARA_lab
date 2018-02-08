# YARA_lab
YARA-based project that allows you to run a set of YARA rules and dynamically build a new ruleset from detections.

# Running Yaralab.py

Before running the script make sure the yara files you want to have access to for follow-up tests are in **Algoyara/yarafiles** folder. In Algoyara, there is a **rulemap.json** file that dictates the logic map for follow up tests. It organized by a list of objects that have 'rule' and 'run' tags in them. 'rule' is the rule that matched, run is a list of rules to run based on that match. 

Make sure ALL *POSSIBLE RULES* are in the yarafiles folder otherwise they won't run.

Once you've set that up, simply run 'python yaralab.py' from the command line. yaralab starts Algorithmic-Yara.py which runs in a while loop until the user types 'quit' into the command line. 

To test files in yaralab simply drop them into the **00_processing folder**. These files will be processed and moved to **01_finished folder** after complete. Files in the **01_finished** folder will not be processed again.

Have fun! Let me know about any bugs you might come across.
