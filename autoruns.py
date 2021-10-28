# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Simple data source-level ingest module for Autopsy.
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/latest/index.html for documentation

import inspect
import os
import shutil
import ntpath

from java.io import File
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import Arrays
from java.util import Calendar, GregorianCalendar
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Blackboard
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.modules.interestingitems import FilesSetsManager

# UI Settings Imports
from javax.swing import JCheckBox
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JFileChooser
from javax.swing import JScrollPane
from javax.swing.filechooser import FileNameExtensionFilter

# Registry Interaction imports
from com.williballenthin.rejistry import RegistryHiveFile
from com.williballenthin.rejistry import RegistryKey
from com.williballenthin.rejistry import RegistryParseException
from com.williballenthin.rejistry import RegistryValue

# Scheduled Tasks imports
import json
import winjob

# Startup Programs imports
from datetime import datetime

# Services imports
import re


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class AutoRunsModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Autoruns"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Looks at Auto-Start Extensibility Points (ASEP) and list out potential persistence"

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return AutorunsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return AutoRunsIngestModule(self.settings)


# Data Source-level ingest module.  One gets created per data source.
class AutoRunsIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(AutoRunsModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        
        self.context = context

        # Hive Keys to parse, use / as it is easier to parse out then \\

        if self.local_settings.getSetting('Registry_Runs') == 'true':
            self.log(Level.INFO, "Registry Runs ==> " + str(self.local_settings.getSetting('Registry_Runs')))
            
            # HKLM\Software\
            self.registrySoftwareRunKeys = (
                'Microsoft/Windows/CurrentVersion/Run', 
                'Microsoft/Windows/CurrentVersion/RunOnce',
                'Microsoft/Windows/CurrentVersion/RunOnceEx',
                'Microsoft/Windows/CurrentVersion/RunServices',
                'Microsoft/Windows/CurrentVersion/Policies/Explorer/Run',
                'WOW6432Node/Microsoft/Windows/CurrentVersion/Run',
                'WOW6432Node/Microsoft/Windows/CurrentVersion/RunOnce',
                'WOW6432Node/Microsoft/Windows/CurrentVersion/Policies/Explorer/Run',
                'Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/Run',
                'Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/RunOnce',
                'Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/RunOnceEx',
                #'Microsoft/Windows NT/CurrentVersion/Image File Execution Options',
                #'Classes/CLSID',
                #'Microsoft/Windows NT/CurrentVersion/AppCombatFlags',
                #'Windows/CurrentVersion/Explorer/Browser Helper Objects'
            )

            # HKLM\System\CurrentControlSet
            self.registrySystemRunKeys = {
                'Control/SafeBoot' : 'AlternateShell',
                'Control/Terminal Server/wds/rdpwd': 'StartupPrograms',
                'Control/Terminal Server/WinStations/RDP-Tcp': 'InitialProgram',
            }

            # HKCU\
            self.registryNTUserRunKeys = (
                'Software/Microsoft/Windows/CurrentVersion/Run', 
                'Software/Microsoft/Windows/CurrentVersion/RunOnce',
                'Software/Microsoft/Windows/CurrentVersion/RunServices',
                'Software/Microsoft/Windows/CurrentVersion/RunServicesOnce',
                'Software/Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/Run',
                'Software/Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/RunOnce',
                'Software/Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/RunOnceEx',
                'Software/Microsoft/Windows NT/CurrentVersion/Run',
                'Software/Microsoft/Windows NT/CurrentVersion/Windows/Load',
                'Software/Microsoft/Windows NT/CurrentVersion/Windows/ShellServiceObjectDelayLoad$',
                'Software/Microsoft/Windows NT/CurrentVersion/Windows/Run',
                'Software/Microsoft/Windows NT/CurrentVersion/Winlogon/Shell',
                'Software/Microsoft/Windows/CurrentVersion/Policies/Explorer/Run',
                'Software/Microsoft/Windows/CurrentVersion/Policies/System/Shell',
                'Software/Policies/Microsoft/Windows/System/Scripts/Logon',
                'Software/Policies/Microsoft/Windows/System/Scripts/Logoff'
                'Software/WOW6432Node/Microsoft/Windows/CurrentVersion/Policies/Explorer/Run',
                'Software/WOW6432Node/Microsoft/Windows/CurrentVersion/Run',
                'Software/WOW6432Node/Microsoft/Windows/CurrentVersion/RunOnce',
                #'Software/Classes/Applications',
                #'Software/Classes/CLSID'
            )

            self.registryUserSpecificKeys = {
                'Software/Microsoft/Windows/CurrentVersion/Explorer/User Shell Folders' : 'Startup',
                'Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders' : 'Startup',
            }

            self.registrySoftwareSpecificKeys = {
                'Microsoft/Windows/CurrentVersion/Explorer/User Shell Folders' : 'Common Startup',
                'Microsoft/Windows/CurrentVersion/Explorer/Shell Folders' : 'Common Startup',
                'Microsoft/Windows NT/CurrentVersion/Windows' : 'AppInit_DLLs'
            }

        if self.local_settings.getSetting('Winlogon') == 'true':
            self.log(Level.INFO, "Winlogon ==> " + str(self.local_settings.getSetting('Winlogon')))
         
            # Winlogon & AppInit
            self.registryWinlogonAppinit = (
                'Microsoft/Windows NT/CurrentVersion/Winlogon',  # Value AppInit_DLLs
                'Microsoft/Windows NT/CurrentVersion/Winlogon/Notify',
                'Microsoft/Windows NT/CurrentVersion/Winlogon/Userinit',
                'Microsoft/Windows NT/CurrentVersion/Winlogon/VmApplet',
                'Microsoft/Windows NT/CurrentVersion/Winlogon/Shell',
                'Microsoft/Windows NT/CurrentVersion/Winlogon/TaskMan',
                'Microsoft/Windows NT/CurrentVersion/Winlogon/System'
            )

        if self.local_settings.getSetting('Services') == 'true':
            self.log(Level.INFO, "Services ==> " + str(self.local_settings.getSetting('Services')))

            # Services
            self.serviceTypes = {
                0x001: "Kernel driver",
                0x002: "File system driver",
                0x004: "Arguments for adapter",
                0x008: "File system driver",
                0x010: "Win32_Own_Process",
                0x020: "Win32_Share_Process",
                0x050: "User_Own_Process TEMPLATE",
                0x060: "User_Share_Process TEMPLATE",
                0x0D0: "User_Own_Process INSTANCE",
                0x0E0: "User_Share_Process INSTANCE",
                0x100: "Interactive",
                0x110: "Interactive",
                0x120: "Share_process Interactive",
                -1: "Unknown",
            }

            self.serviceStartup = {
                0x00: "Boot Start",
                0x01: "System Start",
                0x02: "Auto Start",
                0x03: "Manual",
                0x04: "Disabled",
                -1: "Unknown",
            }

        if self.local_settings.getSetting('Scheduled_Tasks') == 'true':
            self.log(Level.INFO, "Scheduled Tasks ==> " + str(self.local_settings.getSetting('Scheduled_Tasks')))

            # Scheduled Tasks
            self.ScheduledTasksLoc = '/Windows/System32/Tasks'

        if self.local_settings.getSetting('Active_Setup') == 'true':
            self.log(Level.INFO, "Active Setup ==> " + str(self.local_settings.getSetting('Active_Setup')))

            # Active Setup
            self.registryActiveSetup = (
                'Microsoft/Active Setup/Installed Components'
            )

        if self.local_settings.getSetting('Registry_Fixit') == 'true':
            self.log(Level.INFO, "Registry Fix-it ==> " + str(self.local_settings.getSetting('Registry_Fixit')))

            # Microsoft Fix-it
            self.registryFixit = (
                'Microsoft/Windows NT/CurrentVersion/AppCompatFlags/InstalledSDB'
            )

        if self.local_settings.getSetting('Startup_Program') == 'true':
            self.log(Level.INFO, "Startup Program ==> " + str(self.local_settings.getSetting('Startup_Program')))

            # Startup folder
            self.startupProgram = (
                #'/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup',                    # Startup path for all users
                '%/Microsoft/Windows/Start Menu/Programs/Startup'      # Startup path for current user
            )

        if self.local_settings.getSetting('CLSID') == 'true':
            self.log(Level.INFO, "CLSID ==> " + str(self.local_settings.getSetting('CLSID')))

            # HKCR CLSID
            self.CLSID = (
                'CLSID'
            )

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process persistent keys")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Registry Runs
        if self.local_settings.getSetting('Registry_Runs') == 'true':
            progressBar.progress("Processing Registry Run Keys")
            self.process_Registry_Runs(dataSource, progressBar)

            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Autoruns", " Registry Run Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        # WinLogon
        if self.local_settings.getSetting('Winlogon') == 'true':
            progressBar.progress("Processing Winlogon Keys")
            self.process_Winlogon(dataSource, progressBar)

            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Autoruns", " Winlogon Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        # Services
        if self.local_settings.getSetting('Services') == 'true':
            progressBar.progress("Processing Services")
            self.process_Services(dataSource, progressBar)

            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Autoruns", " Services Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        # Scheduled Tasks
        if self.local_settings.getSetting('Scheduled_Tasks') == 'true':
            progressBar.progress("Processing Scheduled Tasks")
            self.process_Scheduled_Tasks(dataSource, progressBar)

            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Autoruns", " Scheduled Tasks Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        # Active Setup
        if self.local_settings.getSetting('Active_Setup') == 'true':
            progressBar.progress("Processing Active Setup")
            self.process_Active_Setup(dataSource, progressBar)

            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Autoruns", " Active Setup Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        # Microsoft Fix-it
        if self.local_settings.getSetting('Registry_Fixit') == 'true':
            progressBar.progress("Processing Microsoft Fix-it")
            self.process_Registry_Fixit(dataSource, progressBar)

            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Autoruns", " Registry Fixit Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        # Startup Program
        if self.local_settings.getSetting('Startup_Program') == 'true':
            progressBar.progress("Processing Startup Program")
            self.process_Startup_Program(dataSource, progressBar)

            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Autoruns", " Startup Program Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        # CLSID
        if self.local_settings.getSetting('CLSID') == 'true':
            progressBar.progress("Processing CLSID")
            self.process_CLSID(dataSource, progressBar)

            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Autoruns", " CLSID Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

         # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Autoruns", " Autoruns Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

    def process_Registry_Runs(self, dataSource, progressBar):
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        progressBar.progress("Finding Registry Run Keys")
        self.log(Level.INFO, "Processing Registry Run Keys")

        # Hives files to extract
        filesToExtract = ("NTUSER.DAT", "SOFTWARE", "SYSTEM")

        # Create autoruns directory in temp directory, if it exists then continue on processing      
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autoruns")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
            os.mkdir(tempDir)
        except:
            self.log(Level.INFO, "Autoruns Directory already exists " + tempDir)

        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Setup Artifact and Attributes
        artType = skCase.getArtifactType("TSK_REGISTRY_RUN_KEYS")
        if not artType:
            try:
                artType = skCase.addBlackboardArtifactType( "TSK_REGISTRY_RUN_KEYS", "Registry Run Keys")
            except:     
                self.log(Level.WARNING, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

        try:
            attributeIdRegKeyUser = skCase.addArtifactAttributeType(
                "TSK_REG_KEY_USER",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "User"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_REG_KEY_USER, May already exist. ")

        try:
           attributeIdRunKeyName = skCase.addArtifactAttributeType(
                "TSK_REG_RUN_KEY_NAME", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Run Key Name"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_REG_RUN_KEY_NAME, May already exist. ")
        
        try:
           attributeIdRunKeyValue = skCase.addArtifactAttributeType(
                "TSK_REG_RUN_KEY_VALUE", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Run Key Value"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_REG_RUN_KEY_VALUE, May already exist. ")
        
        try:
           attributeIdRegKeyLoc = skCase.addArtifactAttributeType(
                "TSK_REG_KEY_LOCATION", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Registry Key Location"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_REG_KEY_LOCATION, May already exist. ")

        attributeIdRunKeyName = skCase.getAttributeType("TSK_REG_RUN_KEY_NAME")
        attributeIdRunKeyValue = skCase.getAttributeType("TSK_REG_RUN_KEY_VALUE")
        attributeIdRegKeyLoc = skCase.getAttributeType("TSK_REG_KEY_LOCATION")
        attributeIdRegKeyUser = skCase.getAttributeType("TSK_REG_KEY_USER")

        moduleName = AutoRunsModuleFactory.moduleName

        # Look for files to process
        for fileName in filesToExtract:
            files = fileManager.findFiles(dataSource, fileName)
            numFiles = len(files)

            progressBar.switchToDeterminate(numFiles)

            for file in files:
            
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                # Check path to only get the hive files in the config directory and no others
                if ((file.getName() == 'SOFTWARE') and (file.getParentPath().upper() == '/WINDOWS/SYSTEM32/CONFIG/') and (file.getSize() > 0)):    
                    # Save the file locally in the temp folder. 
                    self.writeHiveFile(file, file.getName(), tempDir)
                    
                    # Process HKLM Software file looking thru the run keys
                    user = "System"
                    self.log(Level.INFO, "SOFTWARE hive exists, parsing it")
                    
                    regFileName = os.path.join(tempDir, file.getName())
                    regFile = RegistryHiveFile(File(regFileName))
                    rootKey = regFile.getRoot()

                    for runKey in self.registrySoftwareRunKeys:
                        #self.log(Level.INFO, "Finding key: " + runKey)

                        currentKey = self.findRegistryKey(rootKey, runKey)
                        if currentKey and len(currentKey.getValueList()) > 0:
                            skValues = currentKey.getValueList()

                            for skValue in skValues:
                                skName = skValue.getName()
                                skVal = skValue.getValue()

                                art = file.newDataArtifact(artType, Arrays.asList(
                                    BlackboardAttribute(attributeIdRegKeyUser, moduleName, user),
                                    BlackboardAttribute(attributeIdRegKeyLoc, moduleName, runKey),
                                    BlackboardAttribute(attributeIdRunKeyName, moduleName, str(skName)),
                                    BlackboardAttribute(attributeIdRunKeyValue, moduleName, str(skVal.getAsString()))
                                ))

                                # index the artifact for keyword search
                                try:
                                    blackboard.postArtifact(art, moduleName)
                                except Blackboard.BlackboardException as ex:
                                    self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)

                    # Process Startup Folder location
                    for runKey in self.registrySoftwareSpecificKeys:
                        #self.log(Level.INFO, "Finding key: " + runKey)
                        startupVal = self.registrySoftwareSpecificKeys[runKey]

                        currentKey = self.findRegistryKey(rootKey, runKey)
                        if currentKey and len(currentKey.getValueList()) > 0:
                            skValues = currentKey.getValueList()

                            for skValue in skValues:
                                if skValue.getName() == startupVal:
                                    skName = skValue.getName()
                                    skVal = skValue.getValue()

                                    art = file.newDataArtifact(artType, Arrays.asList(
                                        BlackboardAttribute(attributeIdRegKeyUser, moduleName, user),
                                        BlackboardAttribute(attributeIdRegKeyLoc, moduleName, runKey),
                                        BlackboardAttribute(attributeIdRunKeyName, moduleName, str(skName)),
                                        BlackboardAttribute(attributeIdRunKeyValue, moduleName, str(skVal.getAsString()))
                                    ))

                                    # index the artifact for keyword search
                                    try:
                                        blackboard.postArtifact(art, moduleName)
                                    except Blackboard.BlackboardException as ex:
                                        self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)

                    
                elif ((file.getName() == 'NTUSER.DAT') and ('/USERS' in file.getParentPath().upper()) and (file.getSize() > 0)):
                # Found a NTUSER.DAT file to process only want files in User directories
                    # Filename may not be unique so add file id to the name
                    fileName = str(file.getId()) + "-" + file.getName()
                    
                    # Save the file locally in the temp folder.
                    self.writeHiveFile(file, fileName, tempDir)

                    # Process NTUSER.DAT file looking thru the run keys
                    #self.processNTUserHive(os.path.join(tempDir, fileName), file)

                    user = file.getParentPath().split('/')[2] 
                    self.log(Level.INFO, "User \'" + user + "\' hive exists, parsing it")
                    
                    regFileName = os.path.join(tempDir, fileName)
                    regFile = RegistryHiveFile(File(regFileName))
                    rootKey = regFile.getRoot()

                    # Process NTUser run keys
                    for runKey in self.registryNTUserRunKeys:
                        #self.log(Level.INFO, "Finding key: " + runKey)

                        currentKey = self.findRegistryKey(rootKey, runKey)
                        if currentKey and len(currentKey.getValueList()) > 0:
                            skValues = currentKey.getValueList()

                            for skValue in skValues:
                                skName = skValue.getName()
                                skVal = skValue.getValue()

                                art = file.newDataArtifact(artType, Arrays.asList(
                                    BlackboardAttribute(attributeIdRegKeyUser, moduleName, user),
                                    BlackboardAttribute(attributeIdRegKeyLoc, moduleName, runKey),
                                    BlackboardAttribute(attributeIdRunKeyName, moduleName, str(skName)),
                                    BlackboardAttribute(attributeIdRunKeyValue, moduleName, str(skVal.getAsString()))
                                ))

                                # index the artifact for keyword search
                                try:
                                    blackboard.postArtifact(art, moduleName)
                                except Blackboard.BlackboardException as ex:
                                    self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)

                    # Process Startup Folder location
                    for runKey in self.registryUserSpecificKeys:
                        #self.log(Level.INFO, "Finding key: " + runKey)
                        startupVal = self.registryUserSpecificKeys[runKey]
                
                        currentKey = self.findRegistryKey(rootKey, runKey)
                        if currentKey and len(currentKey.getValueList()) > 0:
                            skValues = currentKey.getValueList()

                            for skValue in skValues:
                                if skValue.getName() == startupVal:
                                    skName = skValue.getName()
                                    skVal = skValue.getValue()

                                    art = file.newDataArtifact(artType, Arrays.asList(
                                        BlackboardAttribute(attributeIdRegKeyUser, moduleName, user),
                                        BlackboardAttribute(attributeIdRegKeyLoc, moduleName, runKey),
                                        BlackboardAttribute(attributeIdRunKeyName, moduleName, str(skName)),
                                        BlackboardAttribute(attributeIdRunKeyValue, moduleName, str(skVal.getAsString()))
                                    ))

                                    # index the artifact for keyword search
                                    try:
                                        blackboard.postArtifact(art, moduleName)
                                    except Blackboard.BlackboardException as ex:
                                        self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)

                elif ((file.getName() == 'SYSTEM') and (file.getParentPath().upper() == '/WINDOWS/SYSTEM32/CONFIG/') and (file.getSize() > 0)): 
                    # Save the file locally in the temp folder. 
                    self.writeHiveFile(file, file.getName(), tempDir)
                    
                    # Process HKLM Software file looking thru the run keys
                    user = "System"
                    self.log(Level.INFO, "SYSTEM hive exists, parsing it")
                    
                    regFileName = os.path.join(tempDir, file.getName())
                    regFile = RegistryHiveFile(File(regFileName))

                    # Find ControlSets
                    rootKey = regFile.getRoot()
                    subkeys = rootKey.getSubkeyList()
                    for subkey in subkeys:
                        if re.match(r'.*ControlSet.*', subkey.getName()):
                            for runKey in self.registrySystemRunKeys:
                                #self.log(Level.INFO, "Finding key: " + runKey)
                                filterVal = self.registrySystemRunKeys[runKey]

                                currentKey = self.findRegistryKey(subkey, runKey)
                                if currentKey and len(currentKey.getValueList()) > 0:
                                    skValues = currentKey.getValueList()

                                    for skValue in skValues:
                                        if skValue.getName() == filterVal:
                                            skName = skValue.getName()
                                            skVal = skValue.getValue()

                                            art = file.newDataArtifact(artType, Arrays.asList(
                                                BlackboardAttribute(attributeIdRegKeyUser, moduleName, user),
                                                BlackboardAttribute(attributeIdRegKeyLoc, moduleName, subkey.getName() + "/" + runKey),
                                                BlackboardAttribute(attributeIdRunKeyName, moduleName, str(skName)),
                                                BlackboardAttribute(attributeIdRunKeyValue, moduleName, str(skVal.getAsString()))
                                            ))

                                            # index the artifact for keyword search
                                            try:
                                                blackboard.postArtifact(art, moduleName)
                                            except Blackboard.BlackboardException as ex:
                                                self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)
                        


        #Clean up Autoruns directory and files
        try:
            shutil.rmtree(tempDir)      
        except:
            self.log(Level.INFO, "removal of directory tree failed " + tempDir)

    # TODO: Write process_Winlogon
    def process_Winlogon(self, dataSource, progressBar):
        pass

    # TODO: Write process_Services
    def process_Services(self, dataSource, progressBar):
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        progressBar.progress("Finding Services")
        self.log(Level.INFO, "Processing Services")

        # Create autoruns directory in temp directory, if it exists then continue on processing      
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autoruns")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
            os.mkdir(tempDir)
        except:
            self.log(Level.INFO, "Autoruns Directory already exists " + tempDir)

        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Setup Artifact and Attributes
        artType = skCase.getArtifactType("TSK_SERVICE")
        if not artType:
            try:
                artType = skCase.addBlackboardArtifactType( "TSK_SERVICE", "Services")
            except:     
                self.log(Level.WARNING, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

        try:
            attributeIdServiceDisplayName = skCase.addArtifactAttributeType(
                "TSK_SERVICE_DISPLAY_NAME",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "Display Name"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SERVICE_DISPLAY_NAME, May already exist. ")

        try:
           attributeIdServiceTimestamp = skCase.addArtifactAttributeType(
                "TSK_SERVICE_TIMESTAMP", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Timestamp"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SERVICE_TIMESTAMP, May already exist. ")
        
        try:
           attributeIdServiceStartup = skCase.addArtifactAttributeType(
                "TSK_SERVICE_STARTUP", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Startup"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SERVICE_STARTUP, May already exist. ")
        
        try:
           attributeIdServiceType = skCase.addArtifactAttributeType(
                "TSK_SERVICE_TYPE", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Type"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SERVICE_TYPE, May already exist. ")

        try:
           attributeIdServiceImagePath = skCase.addArtifactAttributeType(
                "TSK_SERVICE_IMAGE_PATH", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Image Path"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SERVICE_IMAGE_PATH, May already exist. ")

        try:
           attributeIdServiceServiceDll = skCase.addArtifactAttributeType(
                "TSK_SERVICE_SERVICE_DLL", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Service Dll"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SERVICE_SERVICE_DLL, May already exist. ")

        attributeIdServiceDisplayName = skCase.getAttributeType("TSK_SERVICE_DISPLAY_NAME")
        attributeIdServiceTimestamp = skCase.getAttributeType("TSK_SERVICE_TIMESTAMP")
        attributeIdServiceStartup = skCase.getAttributeType("TSK_SERVICE_STARTUP")
        attributeIdServiceType = skCase.getAttributeType("TSK_SERVICE_TYPE")
        attributeIdServiceImagePath = skCase.getAttributeType("TSK_SERVICE_IMAGE_PATH")
        attributeIdServiceServiceDll = skCase.getAttributeType("TSK_SERVICE_SERVICE_DLL")


        moduleName = AutoRunsModuleFactory.moduleName

        # Extract file
        files = fileManager.findFiles(dataSource, "SYSTEM", "/Windows/System32/Config")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)

        for file in files:
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Name of file: " + file.getParentPath() + file.getName() )

            # Check path to only get the hive files in the config directory and no others
            if ((file.getName() == 'SYSTEM') and (file.getParentPath().upper() == '/WINDOWS/SYSTEM32/CONFIG/') and (file.getSize() > 0)):

                # Save the file locally in the temp folder. 
                self.writeHiveFile(file, file.getName(), tempDir)

                regFileName = os.path.join(tempDir, file.getName())
                regFile = RegistryHiveFile(File(regFileName))

                # Find ControlSets
                rootKey = regFile.getRoot()
                subkeys = rootKey.getSubkeyList()
                for subkey in subkeys:
                    if re.match(r'.*ControlSet.*', subkey.getName()):
                        currentkey = subkey.getSubkey("Services")

                        self.log(Level.INFO, "Current Key: " + currentkey.getName())
                        for servicekey in currentkey.getSubkeyList():
                            #self.log(Level.INFO, "Parsing " + servicekey.getName())
                            
                            # Store values in dictionary
                            values = {}
                            for skValue in servicekey.getValueList():                      
                                #self.log(Level.INFO, "Trying: " + skValue.getName())
                                regType = str(skValue.getValueType())
                                #self.log(Level.INFO, "Type: " + regType)
                                if regType in ["REG_EXPAND_SZ", "REG_SZ"]:
                                    values[skValue.getName()] = skValue.getValue().getAsString()
                                elif regType in ["REG_DWORD", "REG_QWORD", "REG_BIG_ENDIAN"] :
                                    values[skValue.getName()] = skValue.getValue().getAsNumber()
                                elif regType == "REG_MULTI_SZ":
                                    values[skValue.getName()] = list(skValue.getValue().getAsStringList())
                                    

                            #self.log(Level.INFO, "Values: " + json.dumps(values, indent=2))
                            image_path = values.get("ImagePath", "")
                            display_name = values.get("DisplayName", "")
                            service_dll = values.get("ServiceDll", "")
                            main = values.get("ServiceMain", "")
                            startup = values.get("Start", "")
                            service_type = values.get("Type", "")
                            timestamp = servicekey.getTimestamp()

                            # startup 0, 1, 2 are ASEPs
                            if not image_path or startup not in [0, 1, 2]:
                                continue

                            if 'svchost.exe -k' in image_path.lower() or "Share_process" in self.serviceTypes[service_type]:
                                try:
                                    sk = servicekey.getSubkey("Parameters")
                                except:
                                    sk = None

                                # Get serviceDll located in paramters
                                if sk and not service_dll:
                                    timestamp = sk.getTimestamp()
                                    try:
                                        service_dll = sk.getValue("ServiceDll")
                                    except:
                                        service_dll = ""

                                    try:
                                        main = sk.getValue("ServiceMain")
                                    except:
                                        main = ""

                                if not service_dll and '@' in display_name:
                                    timestamp = servicekey.getTimestamp()
                                    service_dll = display_name.split('@')[1].split(',')[0]

                            # self.log(Level.INFO, "Image Path: " + str(image_path) +
                            #     "\nDisplay Name: " + str(display_name) + 
                            #     "\nService Dll: " + str(service_dll) +
                            #     "\nMain: " + str(main) +
                            #     "\nStartup: " + self.serviceStartup[startup] +
                            #     "\nType: " + self.serviceTypes[service_type] +
                            #     "\nTimestamp: " + str(timestamp.toZonedDateTime())
                            # )

                            art = file.newDataArtifact(artType, Arrays.asList(
                                BlackboardAttribute(attributeIdServiceDisplayName, moduleName, str(display_name)),
                                BlackboardAttribute(attributeIdServiceTimestamp, moduleName, str(timestamp.toZonedDateTime())),
                                BlackboardAttribute(attributeIdServiceStartup, moduleName, self.serviceStartup[startup]),
                                BlackboardAttribute(attributeIdServiceType, moduleName, self.serviceTypes[service_type]),
                                BlackboardAttribute(attributeIdServiceImagePath, moduleName, str(image_path)),
                                BlackboardAttribute(attributeIdServiceServiceDll, moduleName, str(service_dll)),
                            ))

                            # index the artifact for keyword search
                            try:
                                blackboard.postArtifact(art, moduleName)
                            except Blackboard.BlackboardException as ex:
                                self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)


                        

            #Clean up Autoruns directory and files
            try:
                shutil.rmtree(tempDir)      
            except:
                self.log(Level.INFO, "removal of directory tree failed " + tempDir)


    # TODO: Write process_Scheduled_Tasks
    def process_Scheduled_Tasks(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        progressBar.progress("Finding Scheduled Tasks")
        self.log(Level.INFO, "Processing Scheduled Tasks")

        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Create autoruns directory in temp directory, if it exists then continue on processing      
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autoruns")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
            os.mkdir(tempDir)
        except:
            self.log(Level.INFO, "Autoruns Directory already exists " + tempDir)


        # Setup Artifact and Attributes
        artType = skCase.getArtifactType("TSK_SCHEDULED_TASKS")
        if not artType:
            try:
                artType = skCase.addBlackboardArtifactType( "TSK_SCHEDULED_TASKS", "Scheduled Tasks")
            except:     
                self.log(Level.WARNING, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

        try:
            attributeIdScheduledTasksURI = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_URI",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "URI"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_URI, May already exist. ")

        try:
           attributeIdScheduledTasksDescription = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_DESCRIPTION", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Description"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_DESCRIPTION, May already exist. ")

        try:
           attributeIdScheduledTasksDate = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_DATE", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Date"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_DATE, May already exist. ")

        try:
            attributeIdScheduledTasksStatus = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_STATUS",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "Status"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_STATUS, May already exist. ")

        try:
           attributeIdScheduledTasksCommand = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_COMMAND", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Command"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_COMMAND, May already exist. ")

        try:
           attributeIdScheduledTasksActions = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_ACTIONS", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Actions"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_COMMAND, May already exist. ")
        
        try:
           attributeIdScheduledTasksTriggers = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_TRIGGERS", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Triggers"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_TRIGGERS, May already exist. ")

        try:
           attributeIdScheduledTasksHidden = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_HIDDEN", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Hidden"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_HIDDEN, May already exist. ")
        
        try:
           attributeIdScheduledTasksDump = skCase.addArtifactAttributeType(
                "TSK_SCHEDULED_TASKS_DUMP", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Dump"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_SCHEDULED_TASKS_DUMP, May already exist. ")

        attributeIdScheduledTasksURI = skCase.getAttributeType("TSK_SCHEDULED_TASKS_URI")
        attributeIdScheduledTasksDescription = skCase.getAttributeType("TSK_SCHEDULED_TASKS_DESCRIPTION")
        attributeIdScheduledTasksDate = skCase.getAttributeType("TSK_SCHEDULED_TASKS_DATE")
        attributeIdScheduledTasksStatus = skCase.getAttributeType("TSK_SCHEDULED_TASKS_STATUS")
        attributeIdScheduledTasksCommand = skCase.getAttributeType("TSK_SCHEDULED_TASKS_COMMAND")
        attributeIdScheduledTasksActions = skCase.getAttributeType("TSK_SCHEDULED_TASKS_ACTIONS")
        attributeIdScheduledTasksTriggers = skCase.getAttributeType("TSK_SCHEDULED_TASKS_TRIGGERS")
        attributeIdScheduledTasksHidden = skCase.getAttributeType("TSK_SCHEDULED_TASKS_HIDDEN")
        attributeIdScheduledTasksDump = skCase.getAttributeType("TSK_SCHEDULED_TASKS_DUMP")

        moduleName = AutoRunsModuleFactory.moduleName

        # Get Scheduled Task files
        filesTemp = fileManager.findFiles(dataSource, "%", self.ScheduledTasksLoc)

        for file in filesTemp:
            if (not file.isDir()):
                #self.log(Level.INFO, "Working on: "  + file.getParentPath() + file.getName())

                # Save the file locally in the temp folder.
                self.writeHiveFile(file, file.getName(), tempDir)

                # Attempt to parse task xml
                filePath = os.path.join(tempDir, file.getName())
                with open(filePath, 'r') as fd:
                    task = winjob.read_task(fd.read())

                # Check if parse worked
                if task != None:
                    #self.log(Level.INFO, "Details of " + file.getName() + " " + json.dumps(task.parse(), indent=2))
                    data = task.parse()

                    uri = data["uri"]
                    description = data["description"] if data["description"] else ""
                    date = data["date"] if data["date"] else ""
                    enabled = data["triggers"][0]["Enabled"] if data["triggers"] else ""
                    command = data["actions"][0]["Command"] if "Command" in data["actions"][0] else ""
                    actions = data["actions"][0] if data["actions"] else ""
                    triggers = data["triggers"][0] if data["triggers"] else ""
                    hidden = data["hidden"] if data["hidden"] else ""

                    status = "Enabled" if enabled == "true" else "Disabled" if enabled == "false" else "" 

                    # self.log(Level.INFO, "File: " + file.getName() +  
                    #     "\nURI: " + uri + 
                    #     "\nStatus: " + status +
                    #     "\nCommand: " + command + 
                    #     "\nTrigger: " + trigger
                    # )

                    # Don't index empty commands
                    if command != "":
                        art = file.newDataArtifact(artType, Arrays.asList(
                            BlackboardAttribute(attributeIdScheduledTasksURI, moduleName, uri),
                            BlackboardAttribute(attributeIdScheduledTasksDescription, moduleName, description),
                            BlackboardAttribute(attributeIdScheduledTasksDate, moduleName, date),
                            BlackboardAttribute(attributeIdScheduledTasksStatus, moduleName, status),
                            BlackboardAttribute(attributeIdScheduledTasksCommand, moduleName, command),
                            BlackboardAttribute(attributeIdScheduledTasksActions, moduleName, json.dumps(actions, indent=2)),
                            BlackboardAttribute(attributeIdScheduledTasksTriggers, moduleName, json.dumps(triggers, indent=2)),
                            BlackboardAttribute(attributeIdScheduledTasksHidden, moduleName, hidden),
                            BlackboardAttribute(attributeIdScheduledTasksDump, moduleName, json.dumps(task.parse(), indent=2))
                        ))

                        # index the artifact for keyword search
                        try:
                            blackboard.postArtifact(art, moduleName)
                        except Blackboard.BlackboardException as ex:
                            self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)


        #Clean up Autoruns directory and files
        try:
            shutil.rmtree(tempDir)      
        except:
            self.log(Level.INFO, "removal of directory tree failed " + tempDir)

    # TODO: Write process_Active_Setup
    def process_Active_Setup(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()

        progressBar.progress("Finding Active Setups")

        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Create autoruns directory in temp directory, if it exists then continue on processing
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autoruns")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
            os.mkdir(tempDir)
        except:
            self.log(Level.INFO, "Autoruns Directory already exists " + tempDir)

        artType = skCase.getArtifactType("TSK_ACTIVE_SETUP")
        if not artType:
            try:
                artType = skCase.addBlackboardArtifactType("TSK_ACTIVE_SETUP", "Active Setups")
            except:
                self.log(Level.WARNING, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

        try:
            attributeIdActiveSetupName = skCase.addArtifactAttributeType(
                "TSK_ACTIVE_SETUP_NAME",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "Name"
            )
        except:
            self.log(Level.INFO, "Attributes Creation Error, TSK_ACTIVE_SETUP_NAME, May already exist. ")

        try:
            attributeIdActiveSetupStubpath = skCase.addArtifactAttributeType(
                "TSK_ACTIVE_SETUP_STUBPATH",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "STUBPATH"
            )
        except:
            self.log(Level.INFO, "Attributes Creation Error, TSK_ACTIVE_SETUP_STUBPATH, May already exist. ")

        try:
            attributeIdActiveSetupComponentID = skCase.addArtifactAttributeType(
                "TSK_ACTIVE_SETUP_COMPONENTID",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "Component ID"
            )
        except:
            self.log(Level.INFO, "Attributes Creation Error, TSK_ACTIVE_SETUP_COMPONENTID, May already exist. ")

        try:
            attributeIdActiveSetupVersion = skCase.addArtifactAttributeType(
                "TSK_ACTIVE_SETUP_VERSION",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "Version"
            )
        except:
            self.log(Level.INFO, "Attributes Creation Error, TSK_ACTIVE_SETUP_VERSION, May already exist. ")

        try:
            attributeIdActiveSetupTimeStamp = skCase.addArtifactAttributeType(
                "TSK_ACTIVE_SETUP_TIMESTAMP",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "Timestamp"
            )
        except:
            self.log(Level.INFO, "Attributes Creation Error, TSK_ACTIVE_SETUP_TIMESTAMP, May already exist. ")


        attributeIdActiveSetupName = skCase.getAttributeType("TSK_ACTIVE_SETUP_NAME")
        attributeIdActiveSetupStubpath = skCase.getAttributeType("TSK_ACTIVE_SETUP_STUBPATH")
        attributeIdActiveSetupComponentID = skCase.getAttributeType("TSK_ACTIVE_SETUP_COMPONENTID")
        attributeIdActiveSetupVersion = skCase.getAttributeType("TSK_ACTIVE_SETUP_VERSION")
        attributeIdActiveSetupTimeStamp = skCase.getAttributeType("TSK_ACTIVE_SETUP_TIMESTAMP")

        moduleName = AutoRunsModuleFactory.moduleName

        files = fileManager.findFiles(dataSource, "SOFTWARE", "/Windows/System32/Config")
        numfiles = len(files)
        progressBar.switchToDeterminate(numfiles)

        for file in files:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Name of file: " + file.getParentPath() + file.getName())

            if ((file.getName() == 'SOFTWARE') and (file.getParentPath().upper() == '/WINDOWS/SYSTEM32/CONFIG/') and (
                    file.getSize() > 0)):
                self.writeHiveFile(file, file.getName(), tempDir)

                regFileName = os.path.join(tempDir, file.getName())
                regFile = RegistryHiveFile(File(regFileName))

                rootkey = regFile.getRoot()
                subkeys = rootkey.getSubkeyList()
                for subkey in subkeys:
                    if re.match(r'Microsoft', subkey.getName()):
                        currentKey = subkey.getSubkey("Active Setup")
                        finalKey = currentKey.getSubkey("Installed Components")

                        self.log(Level.INFO, "Current Key: " + finalKey.getName())
                        for setupkey in finalKey.getSubkeyList():
                            self.log(Level.INFO, "Parsing " + setupkey.getName())

                            values = {}
                            for skValue in setupkey.getValueList():
                                regType = str(skValue.getValueType())
                                if regType in ["REG_EXPAND_SZ", "REG_SZ"]:
                                    values[skValue.getName()] = skValue.getValue().getAsString()
                                elif regType in ["REG_DWORD", "REG_QWORD", "REG_BIG_ENDIAN"]:
                                    values[skValue.getName()] = skValue.getValue().getAsNumber()
                                elif regType == "REG_MULTI_SZ":
                                    values[skValue.getName()] = list(skValue.getValue().getAsStringList())

                            name = values.get("", "")
                            componentid = values.get("ComponentID", "")
                            stubpath = values.get("StubPath", "")
                            version = values.get("Version", "")
                            timeobj = setupkey.getTimestamp
                            timestamp = timeobj.getTime()

                            art = file.newDataArtifact(artType, Arrays.asList(
                                BlackboardAttribute(attributeIdActiveSetupName, moduleName, str(name)),
                                BlackboardAttribute(attributeIdActiveSetupComponentID, moduleName, str(componentid)),
                                BlackboardAttribute(attributeIdActiveSetupStubpath, moduleName, str(stubpath)),
                                BlackboardAttribute(attributeIdActiveSetupVersion, moduleName, str(version)),
                                BlackboardAttribute(attributeIdActiveSetupTimeStamp, moduleName, str(timestamp))
                            ))
                            try:
                                blackboard.postArtifact(art, moduleName)
                            except Blackboard.BlackboardException as ex:
                                self.log(Level.SEVERE,
                                         "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)

    # TODO: Write process_Registry_Fixit
    def process_Registry_Fixit(self, dataSource, progressBar):
        pass

    # TODO: Write process_Startup_Program
    def process_Startup_Program(self, dataSource, progressBar):
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        progressBar.progress("Finding Startup Programs")
        self.log(Level.INFO, "Processing Startup Programs")

        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        
        # Create autoruns directory in temp directory, if it exists then continue on processing      
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autoruns")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
            os.mkdir(tempDir)
        except:
            self.log(Level.INFO, "Autoruns Directory already exists " + tempDir)

        # Setup Artifact and Attributes
        artType = skCase.getArtifactType("TSK_STARTUP_PROGRAMS")
        if not artType:
            try:
                artType = skCase.addBlackboardArtifactType( "TSK_STARTUP_PROGRAMS", "Startup Programs")
            except:     
                self.log(Level.WARNING, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

        try:
            attributeIdScheduledTasksURI = skCase.addArtifactAttributeType(
                "TSK_STARTUP_PROGRAMS_FILE_PATH",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "File Path"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_STARTUP_PROGRAMS_FILE_PATH, May already exist. ")
        
        try:
            attributeIdScheduledTasksURI = skCase.addArtifactAttributeType(
                "TSK_STARTUP_PROGRAMS_FILE_SIZE",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "File Size"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_STARTUP_PROGRAMS_FILE_SIZE, May already exist. ")

        try:
            attributeIdScheduledTasksStatus = skCase.addArtifactAttributeType(
                "TSK_STARTUP_PROGRAMS_DATE_CREATED",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "Date Created"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_STARTUP_PROGRAMS_DATE_CREATED, May already exist. ")

        try:
           attributeIdScheduledTasksCommand = skCase.addArtifactAttributeType(
                "TSK_STARTUP_PROGRAMS_DATE_MODIFIED", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Date Modified"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_STARTUP_PROGRAMS_COMMAND, May already exist. ")
        
        try:
           attributeIdScheduledTasksTrigger = skCase.addArtifactAttributeType(
                "TSK_STARTUP_PROGRAMS_DATE_ACCESSED", 
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                "Date Accessed"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_STARTUP_PROGRAMS_DATE_ACCESSED, May already exist. ")
        
        attributeIdStartUpProgramsFilePath = skCase.getAttributeType("TSK_STARTUP_PROGRAMS_FILE_PATH")
        attributeIdStartUpProgramsFileSize = skCase.getAttributeType("TSK_STARTUP_PROGRAMS_FILE_SIZE")
        attributeIdStartUpProgramsDateCreated = skCase.getAttributeType("TSK_STARTUP_PROGRAMS_DATE_CREATED")
        attributeIdStartUpProgramsDateModified = skCase.getAttributeType("TSK_STARTUP_PROGRAMS_DATE_MODIFIED")
        attributeIdStartUpProgramsDateAccessed = skCase.getAttributeType("TSK_STARTUP_PROGRAMS_DATE_ACCESSED")

        moduleName = AutoRunsModuleFactory.moduleName

        # Get Startup Program files
        filesTemp = fileManager.findFiles(dataSource, "%", self.startupProgram)
        
        for file in filesTemp:

            # check if cancel was pressed
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            if (not file.isDir()):
                # self.log(Level.INFO, "Working on: "  + file.getParentPath() + file.getName())

                # Save the file locally in the temp folder.
                self.writeHiveFile(file, file.getName(), tempDir)
                filePath = os.path.join(tempDir, file.getName())

                file_path = self.startupProgram
                file_size = os.path.getsize(filePath)
                #date_created = datetime.utcfromtimestamp(os.path.getctime(filePath)).strftime('%Y-%m-%d %H:%M:%S')
                date_created = datetime.utcfromtimestamp(os.path.getctime(filePath)).strftime('%Y-%m-%d %H:%M:%S')
                date_modified = datetime.utcfromtimestamp(os.path.getmtime(filePath)).strftime('%Y-%m-%d %H:%M:%S')
                date_accessed = datetime.utcfromtimestamp(os.path.getatime(filePath)).strftime('%Y-%m-%d %H:%M:%S')
                
                # status = "Enabled" if enabled == "true" else "Disabled" if enabled == "false" else "" 
        
                art = file.newDataArtifact(artType, Arrays.asList(
                    BlackboardAttribute(attributeIdStartUpProgramsDateCreated, moduleName, str(date_created)),
                    BlackboardAttribute(attributeIdStartUpProgramsDateModified, moduleName, str(date_modified)),
                    BlackboardAttribute(attributeIdStartUpProgramsDateAccessed, moduleName, str(date_accessed)),
                    BlackboardAttribute(attributeIdStartUpProgramsFileSize, moduleName, str(file_size)),
                    BlackboardAttribute(attributeIdStartUpProgramsFilePath, moduleName, file_path)
                ))

                
                # index the artifact for keyword search
                try:
                    blackboard.postArtifact(art, moduleName)
                except Blackboard.BlackboardException as ex:
                    self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)


        #Clean up Autoruns directory and files
        try:
            shutil.rmtree(tempDir)      
        except:
            self.log(Level.INFO, "removal of directory tree failed " + tempDir)

    # TODO: Write process_CLSID
    def process_CLSID(self, dataSource, progressBar):
        pass

    def shutDown(self):
        #Clean up Autoruns directory and files

        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autoruns")
        try:
            shutil.rmtree(tempDir)      
        except:
            self.log(Level.INFO, "removal of directory tree failed " + tempDir)

    ####################
    # Helper Functions #
    ####################
    def writeHiveFile(self, file, fileName, tempDir):
        # Write the file to the temp directory.  
        filePath = os.path.join(tempDir, fileName)
        if not os.path.isfile(filePath):
            ContentUtils.writeToFile(file, File(filePath))
        else:
            self.log(Level.INFO, filePath + " Exists, not writing it.")

    def findRegistryKey(self, rootKey, registryKey):
        # Search for the registry key
        regKeyList = registryKey.split('/')
        currentKey = rootKey
        try:
            for key in regKeyList:
                currentKey = currentKey.getSubkey(key) 
            return currentKey
        except:
            self.log(Level.INFO, "Unable to parse key: " + key)
            return None
    
# UI that is shown to user for each ingest job so they can configure the job.
class AutorunsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'
    
    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()
    
    def checkBoxEvent(self, event):

        if self.RegistryRuns_CB.isSelected():
            self.local_settings.setSetting('Registry_Runs', 'true')
        else:
            self.local_settings.setSetting('Registry_Runs', 'false')

        if self.Winlogon_CB.isSelected():
            self.local_settings.setSetting('Winlogon', 'true')
        else:
            self.local_settings.setSetting('Winlogon', 'false')

        if self.Services_CB.isSelected():
            self.local_settings.setSetting('Services', 'true')
        else:
            self.local_settings.setSetting('Services', 'false')

        if self.ScheduledTasks_CB.isSelected():
            self.local_settings.setSetting('Scheduled_Tasks', 'true')
        else:
            self.local_settings.setSetting('Scheduled_Tasks', 'false')

        if self.ActiveSetup_CB.isSelected():
            self.local_settings.setSetting('Active_Setup', 'true')
        else:
            self.local_settings.setSetting('Active_Setup', 'false')

        if self.Fixit_CB.isSelected():
            self.local_settings.setSetting('Registry_Fixit', 'true')
        else:
            self.local_settings.setSetting('Registry_Fixit', 'false')

        if self.Startup_CB.isSelected():
            self.local_settings.setSetting('Startup_Program', 'true')
        else:
            self.local_settings.setSetting('Startup_Program', 'false')

        if self.CLSID_CB.isSelected():
            self.local_settings.setSetting('CLSID', 'true')
        else:
            self.local_settings.setSetting('CLSID', 'false')

    def initComponents(self):
        self.panel0 = JPanel()

        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.RegistryRuns_CB = JCheckBox( "Registry Runs", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.RegistryRuns_CB, self.gbcPanel0 ) 
        self.panel0.add( self.RegistryRuns_CB ) 

        self.Winlogon_CB = JCheckBox( "Winlogon", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Winlogon_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Winlogon_CB ) 

        self.Services_CB = JCheckBox( "Services", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Services_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Services_CB ) 

        self.ScheduledTasks_CB = JCheckBox( "Scheduled Tasks", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.ScheduledTasks_CB, self.gbcPanel0 ) 
        self.panel0.add( self.ScheduledTasks_CB ) 

        self.ActiveSetup_CB = JCheckBox( "Active Setup", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 13 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.ActiveSetup_CB, self.gbcPanel0 ) 
        self.panel0.add( self.ActiveSetup_CB ) 

        self.Fixit_CB = JCheckBox( "Microsoft Fix-it", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Fixit_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Fixit_CB ) 

        self.Startup_CB = JCheckBox( "Startup Program", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 17 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Startup_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Startup_CB ) 

        self.CLSID_CB = JCheckBox( "CLSID", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 19
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.CLSID_CB, self.gbcPanel0 ) 
        self.panel0.add( self.CLSID_CB ) 

        self.add(self.panel0)

    def customizeComponents(self):
        self.RegistryRuns_CB.setSelected(self.local_settings.getSetting('Registry_Runs') == 'true')
        self.Winlogon_CB.setSelected(self.local_settings.getSetting('Winlogon') == 'true')
        self.Services_CB.setSelected(self.local_settings.getSetting('Services') == 'true')
        self.ScheduledTasks_CB.setSelected(self.local_settings.getSetting('Scheduled_Tasks') == 'true')
        self.ActiveSetup_CB.setSelected(self.local_settings.getSetting('Active_Setup') == 'true')
        self.Fixit_CB.setSelected(self.local_settings.getSetting('Registry_Fixit') == 'true')
        self.Startup_CB.setSelected(self.local_settings.getSetting('Startup_Program') == 'true')
        self.CLSID_CB.setSelected(self.local_settings.getSetting('CLSID') == 'true')

    # Return the settings used
    def getSettings(self):
        return self.local_settings