# Autopsy Autoruns Plugin

## Overall Idea
Autopsy plugin that scans the Auto-Start Extensibility Points (ASEPs) and list out the potential persistences

## TODO / Roadmap
- [x] Figure out how to import modules into Autopsy
- [x] Have a disk image to test on
- [x] Be able to run RegistryExample plugin
- [x] Figure out where the logging is located
- [ ] Get list of ASEPs
- [x] Figure out how to write module
- [ ] Write Module
	- [x] Registry Run Keys
    - [x] Scheduled Tasks
    - [x] Services
    - [ ] Active Setup
    - [ ] WinLogon
    - [x] Startup Folder
- [ ] Get GUI to display like autoruns
- [ ] Write Report
- [ ] ORD

## Importing python modules into Autopsy
After opening a case, Tools > Python Module

Create a folder inside the python_module folder and place your python file there
You'll see the ingest module when you do Tool > Run Ingest Module

## Log location
Help > Open Log Folder

autopsy.log.0 is the current running log

## Debugging notes

Always check the log

if you encounter an error whereby the program crashes, high chance whatever file actions you were doing will be locked causing the second instance to create a temp file to fail. To solve this, you need to close and re-open autopsy.

## References
- Installing Python Module (http://sleuthkit.org/autopsy/docs/user-docs/4.19.2/module_install_page.html)
- Autopsy Python Development Set Up (https://www.sleuthkit.org/autopsy/docs/api-docs/4.3/mod_dev_py_page.html)
- File Ingest Module Tutorial (https://www.autopsy.com/python-autopsy-module-tutorial-1-the-file-ingest-module/)
- Data Source Module Tutorial (https://www.autopsy.com/python-autopsy-module-tutorial-2-the-data-source-ingest-module/)
- Report Module Tutorial (https://www.autopsy.com/python-autopsy-module-tutorial-3-the-report-module/)
- Python Modules Examples (https://github.com/sleuthkit/autopsy/tree/develop/pythonExamples)
- Volatility Autoruns Plugin which contains ASEPs to reference from (https://github.com/tomchop/volatility-autoruns)
- ASEP read (https://www.sciencedirect.com/science/article/pii/S1742287619300362)
- Some outdated python module guide (http://www.osdfcon.org/presentations/2018/Eugene-Livis-Writing-Autopsy-Python-Modules.pdf)
- This guy has a ton of modules (https://github.com/markmckinnon/Autopsy-Plugins)
- Rejistry Java file for method reference (https://github.com/williballenthin/Rejistry)
- More ASEP by mitre (https://attack.mitre.org/techniques/T1547/001/)
- Windows Registry Forensics book (https://books.google.com.sg/books?id=BtVtBgAAQBAJ&pg=PA1#v=onepage&q&f=false)
- Another Startup locations reference (https://www.anvir.com/windows-startup-programs-xp.htm)
- Active Setup Explained - (https://helgeklein.com/blog/active-setup-explained/)