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

from javax.swing import JCheckBox
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JFileChooser
from javax.swing import JScrollPane
from javax.swing.filechooser import FileNameExtensionFilter

from com.williballenthin.rejistry import RegistryHiveFile
from com.williballenthin.rejistry import RegistryKey
from com.williballenthin.rejistry import RegistryParseException
from com.williballenthin.rejistry import RegistryValue

from java.io import File
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import Arrays
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
        return AutoRunsIngestModule()


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
                'Microsoft/Windows/CurrentVersion/RunServices',
                'Microsoft/Windows/CurrentVersion/Policies/Explorer/Run',
                'WOW6432Node/Microsoft/Windows/CurrentVersion/Run',
                'WOW6432Node/Microsoft/Windows/CurrentVersion/RunOnce',
                'WOW6432Node/Microsoft/Windows/CurrentVersion/Policies/Explorer/Run',
                'Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/Run',
                'Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/RunOnce',
                'Microsoft/Windows NT/CurrentVersion/Image File Execution Options',
                'Classes/CLSID',
                'Microsoft/Windows NT/CurrentVersion/AppCombatFlags',
                'Windows/CurrentVersion/Explorer/Browser Helper Objects'
            )

            # HKCU\
            self.registryNTUserRunKeys = (
                'Software/Microsoft/Windows/CurrentVersion/Run', 
                'Software/Microsoft/Windows/CurrentVersion/RunOnce',
                'Software/Microsoft/Windows/CurrentVersion/RunServices',
                'Software/Microsoft/Windows/CurrentVersion/RunServicesOnce',
                'Software/Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/Run',
                'Software/Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/RunOnce',
                'Software/Microsoft/Windows NT/CurrentVersion/Run',
                'Software/WOW6432Node/Microsoft/Windows/CurrentVersion/Policies/Explorer/Run',
                'Software/WOW6432Node/Microsoft/Windows/CurrentVersion/Run',
                'Software/Classes/Applications',
                'Software/Classes/CLSID'
            )
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
            self.registryServices = (
                'CurrentControlSet/Services'
            )

        if self.local_settings.getSetting('Scheduled_Tasks') == 'true':
            self.log(Level.INFO, "Scheduled Tasks ==> " + str(self.local_settings.getSetting('Scheduled_Tasks')))

            # Scheduled Tasks
            self.FileSystemScheduledTasks = (
                'C:\\Windows\\System32\\Tasks'
            )

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
                'Microsoft/Windows/Start Menu/Programs/Startup'     # Different root folder, same subpath
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

    # TODO: Write process_Registry_Runs
    def process_Registry_Runs(self, dataSource, progressBar):
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Hives files to extract
        filesToExtract = ("NTUSER.DAT", "SOFTWARE")

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

        try:
            attributeIdRegKeyUser = skCase.addArtifactAttributeType(
                "TSK_REG_KEY_USER",
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                "User"
            )
        except:     
           self.log(Level.INFO, "Attributes Creation Error, TSK_REG_KEY_USER, May already exist. ")

        attributeIdRunKeyName = skCase.getAttributeType("TSK_REG_RUN_KEY_NAME")
        attributeIdRunKeyValue = skCase.getAttributeType("TSK_REG_RUN_KEY_VALUE")
        attributeIdRegKeyLoc = skCase.getAttributeType("TSK_REG_KEY_LOCATION")
        attributeIdRegKeyUser = skCase.getAttributeType("TSK_REG_KEY_USER")

        moduleName = RegistryExampleIngestModuleFactory.moduleName

        # Look for files to process
        for fileName in filesToExtract:
            files = fileManager.findFiles(dataSource, fileName)
            numFiles = len(files)

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
                    regFile = registryHiveFile(File(regFileName))

                    for runKey in self.registrySoftwareRunKeys:
                        self.log(Level.INFO, "Finding key: " + runKey)

                        currentKey = self.findRegistryKey(regFile, runKey)
                        if currentKey and Len(currentKey.getValueList()) > 0:
                            skValues = currentKey.getValueList()

                            for skValue in skValues:
                                art = file.newDataArtifact(artType, Arrays.asList(
                                    BlackboardAttribute(attributeIdRegKeyUser, moduleName, user),
                                    BlackboardAttribute(attributeIdRegKeyLoc, moduleName, runKey),
                                    BlackboardAttribute(attributeIdRunKeyName, moduleName, str(skValue.getName())),
                                    BlackboardAttribute(attributeIdRunKeyName, moduleName, skValue.getValue().getAsString())
                                ))


                    
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
                    
                    regFileName = os.path.join(tempDir, file.getName())
                    regFile = registryHiveFile(File(regFileName))

                    for runKey in self.registryNTUserRunKeys:
                        self.log(Level.INFO, "Finding key: " + runKey)

                        currentKey = self.findRegistryKey(regFile, runKey)
                        if currentKey and Len(currentKey.getValueList()) > 0:
                            skValues = currentKey.getValueList()

                            for skValue in skValues:
                                art = file.newDataArtifact(artType, Arrays.asList(
                                    BlackboardAttribute(attributeIdRegKeyUser, moduleName, user),
                                    BlackboardAttribute(attributeIdRegKeyLoc, moduleName, runKey),
                                    BlackboardAttribute(attributeIdRunKeyName, moduleName, str(skValue.getName())),
                                    BlackboardAttribute(attributeIdRunKeyName, moduleName, skValue.getValue().getAsString())
                                ))

                                # index the artifact for keyword search
                                try:
                                    blackboard.postArtifact(art, moduleName)
                                except Blackboard.BlackboardException as ex:
                                    self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)


        #Clean up registryExample directory and files
        try:
            shutil.rmtree(tempDir)      
        except:
            self.log(Level.INFO, "removal of directory tree failed " + tempDir)

    # TODO: Write process_Winlogon
    def process_Winlogon(self, dataSource, progressBar):
        pass

    # TODO: Write process_Services
    def process_Services(self, dataSource, progressBar):
        pass

    # TODO: Write process_Scheduled_Tasks
    def process_Scheduled_Tasks(self, dataSource, progressBar):
        pass

    # TODO: Write process_Active_Setup
    def process_Active_Setup(self, dataSource, progressBar):
        pass

    # TODO: Write process_Registry_Fixit
    def process_Registry_Fixit(self, dataSource, progressBar):
        pass

    # TODO: Write process_Startup_Program
    def process_Startup_Program(self, dataSource, progressBar):
        pass

    # TODO: Write process_CLSID
    def process_CLSID(self, dataSource, progressBar):
        pass

    ####################
    # Helper Functions #
    ####################
    def writeHiveFile(self, file, fileName, tempDir):
        # Write the file to the temp directory.  
        filePath = os.path.join(tempDir, fileName)
        ContentUtils.writeToFile(file, File(filePath))

    def findRegistryKey(self, registryHiveFile, registryKey):
        # Search for the registry key
        rootKey = registryHiveFile.getRoot()
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