import logging
from typing import Iterable, Tuple, List, Dict, Any

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import resources
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise

try:
    import volatility3.plugins.sqlite_helper as sqlite_helper
except ImportError:
    vollog.info("Sqlite_helper plugin not found")

class YaraScanner(interfaces.layers.ScannerInterface):
    _version = (2, 0, 0)

    # yara.Rules isn't exposed, so we can't type this properly
    def __init__(self, rules) -> None:
        super().__init__()
        if rules is None:
            raise ValueError("No rules provided to YaraScanner")
        self._rules = rules

    def __call__(self, data: bytes, data_offset: int) -> Iterable[Tuple[int, str, str, bytes]]:
        for match in self._rules.match(data = data):
            for offset, name, value in match.strings:
                yield (offset + data_offset, match.rule, name, value)

class ChromeHistory(plugins.PluginInterface):
    """Scans kernel memory to extract URLs table using yara rules"""
    
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = "Memory layer for the kernel",
                                                     architectures = ["Intel32", "Intel64"]),
        ]

    def _generator(self):
        
        """
        Yara rule to which searches for the header of each entry of URLs table.
        
        id -> 00 (always NULL)
        url -> variable   (part of [2-4])
        title -> variable (part of [2-4]) 
        visit_count -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
        typed_count -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
        last_visit_time -> 4 byte integer (06)
        hidden -> (09 | 08 | 01) (1 byte integer, can be 0 or 1)
        """
        #rules = yara.compile(sources = {'n': 'rule URL_HEADER { strings: $a = { 00 [2-4] ( 09 | 08 | 01 ) ( 09 | 08 | 01 ) 06 ( 08 | 01 )} condition: $a }' })
        rules = yara.compile(sources = {'n': 'rule URL_HEADER { strings: $a = { 00 [2-4] ( 09 | 08 | 01 ) ( 09 | 08 | 01 ) 06 ( 08 | 01 )} condition: $a }' })
        
        layer = self.context.layers[self.config['primary']]
        
        for offset, rule_name, name, value in layer.scan(context = self.context, scanner = YaraScanner(rules = rules)):
            
            # Attempt to read memory, will fail if memory is not there (swapped)
            try:
                chrome_buf = layer.read(offset, 60)
            except:
                continue
            
            # Extract header information
            print(chrome_buf)
            
            


            #yield 0, (rowid

    def run(self):
        return renderers.TreeGrid(
            [('Id', int), ('Url', str), ('title', str), ('visit_count', int), ('typed_count', int), ('last_visit_time', str), ('hidden', int)],
            self._generator()
        )