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

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.datamodel import Score
from java.util import Arrays

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
# TODO: Rename this to something more specific. Search and replace for it because it is used a few times
class AutoRunsModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Sample Data Source Module"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Looks at Auto-Start Extensibility Points (ASEP) and list out potential persistence"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        # TODO: Change the class name to the name you'll make below
        return AutoRunsIngestModule()


# Data Source-level ingest module.  One gets created per data source.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
class AutoRunsIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(AutoRunsModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        self.context = context
        # Hive Keys to parse, use / as it is easier to parse out then \\
        
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
            'Microsoft/Windows NT/CurrentVersion/Terminal Server/Install/Software/Microsoft/Windows/CurrentVersion/RunOnce'
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
            'Software/WOW6432Node/Microsoft/Windows/CurrentVersion/Run'
        )

        # Winlogon & AppInit
        self.registryWinlogonAppinit = (
            'Microsoft\Windows NT\CurrentVersion\Winlogon',  # Value AppInit_DLLs
            'Microsoft\Windows NT\CurrentVersion\Winlogon\Notify',
            'Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
            'Microsoft\Windows NT\CurrentVersion\Winlogon\VmApplet',
            'Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
            'Microsoft\Windows NT\CurrentVersion\Winlogon\TaskMan',
            'Microsoft\Windows NT\CurrentVersion\Winlogon\System'
        )

        # Services
        self.registryServices = (
            'CurrentControlSet\Services'
        )

        # Scheduled Tasks
        self.FileSystemScheduledTasks = (
            'C:\Windows\System32\Tasks\\'
        )

        # Active Setup
        self.registryActiveSetup = (
            'Microsoft\Active Setup\Installed Components'
        )

        # Microsoft Fix-it
        self.registryFixit = (
            'Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB'
        )


    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()

        # For our example, we will use FileManager to get all
        # files with the word "test"
        # in the name and then count and read them
        # FileManager API: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1casemodule_1_1services_1_1_file_manager.html
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%test%")

        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # artfiact.  Refer to the developer docs for other examples.
            attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                      AutoRunsModuleFactory.moduleName,
                                                      "Test file"))
            art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT, Score.SCORE_LIKELY_NOTABLE,
                                         None, "Test file", None, attrs).getAnalysisResult()

            try:
                # post the artifact for listeners of artifact events.
                blackboard.postArtifact(art, AutoRunsModuleFactory.moduleName)
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            # To further the example, this code will read the contents of the file and count the number of bytes
            inputStream = ReadContentInputStream(file)
            buffer = jarray.zeros(1024, "b")
            totLen = 0
            readLen = inputStream.read(buffer)
            while (readLen != -1):
                totLen = totLen + readLen
                readLen = inputStream.read(buffer)


            # Update the progress bar
            progressBar.progress(fileCount)


        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Sample Jython Data Source Ingest Module", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK