<<<<<<< HEAD
# Autopsy Autoruns Plugin

## Overall Idea
Autopsy plugin that scans the Auto-Start Extensibility Points (ASEPs) and list out the potential persistences

## TODO / Roadmap
- [ ] Figure out how to import modules into Autopsy
- [ ] Have a disk image to test on
- [ ] Be able to run RegistryExample plugin
- [ ] Figure out where the logging is located
- [ ] Get list of ASEPs
- [ ] Figure out how to write module
- [ ] Write Module
- [ ] Get GUI to display like autoruns
- [ ] Write Report
- [ ] ORD

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
=======
# Private browser memory forensics

## Browsers to look at 
- Chrome
- Firefox
- Internet Explorer
- Edge
- Vivaldi

## Instructions for memory capture
- Download the windows vm [here](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
- Run vm with 4GB ram
- Transfer your browser installer to the vm **DO NOT DOWNLOAD IT ON THE BROWSER**
- See below for the things you are to browse
- Do not close the browsers
- Run Belkasoft Ramcapturer

## What to capture
Chrome:
- www.google.com
- search for "brave browser"
- go to brave site, download brave installer
- www.youtube.com
- search for rick roll
- watch it 

Edge:
- www.google.com
- search for "firefox"
- go to firefox site, download firefox installer
- www.youtube.com
- search for rick roll
- watch it

The rest:
- duckduckgo.com
- search for malware
- go to wikipedia page for malware https://en.wikipedia.org/wiki/Malware
- log in to wikipedia
  - cyberdokutah
  - dokutah1!
- duckduckgo.com
- search for rick roll
  - go to images, right click download image by

# Volatility setup
```
git clone https://github.com/volatilityfoundation/volatility3.git
python3 -m pip install -r requirements.txt
python3 setup.py build 
python3 setup.py install
```

# Running volatility
```
cd <project directory here>
vol -f <mem file> --plugin-dir . chrome_history
```

# Wei Jie's notes
For chromium based browsers, I'm searching for the leaf headers using yara

So far I have come up with the rule for the URL table of the History file

```plaintext
id -> 00 (always NULL, takes the row_id as the id)
url -> variable length, can be as long as 2 bytes  (part of [2-4])
title -> variable length, can be as long as 2 bytes (part of [2-4]) 
visit_count -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
typed_count -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
last_visit_time -> 4 byte integer (06)
hidden -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
```

So far I've only seen hidden being 0 or 1 and nothing else but from superponible's history needle it included `\x01\x01http` which searches for hex 01 in hidden and last_visit_time which doesn't seem to make sense.

```yara
rule URL_HEADER { 
  strings: 
    $a = { 00 [2-4] ( 09 | 08 | 01 ) ( 09 | 08 | 01 ) 06 ( 08 | 01 ) } 
  condition: 
    $a 
}
```


# References
- Chrome & firefox history by superponible (https://github.com/superponible/volatility-plugins)
- Chrome Ragamuffin by cube0x8 (https://github.com/cube0x8/chrome_ragamuffin)
- SqliteFind by mbrown1413 (https://github.com/mbrown1413/SqliteFind)
- Reading sqlite files at the hex level (https://askclees.com/2020/11/20/sqlite-databases-at-hex-level/)
>>>>>>> eb9ac6978b6ee778598e8510e8201c04f8713ff0
