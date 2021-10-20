# Understanding how to write plugins

Ok here's some context on how volatility plugins work.

# Symbols
Before a plugin is ran, it reads through list of profiles to get the right one that matches the memory's operating system version
It then creates a `context` based on the symbol.

context are just handy information for us to easily reference things 

# Plugin interface
Each plugin is a `class` object that inherits the `interfaces.layers.ScannerInterface`

In each plugin there are **3** main functions to be written
- get_requirements
- \_generator
- run 

## get_requirements function
The `get_requirements` function has to be '@classmethod' as it is called before creating an object
The purpose of this function is to:
- load modules
- load plugins
- load layers
- create plugin arguments eg. "--search"

all these are loaded onto the `self.config` variable. 
for example, if you load the module `kernel` as below, you can reference it with `self.config['kernel']`
```python
requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                               architectures = ["Intel32", "Intel64"]),
```

another example, if you created an argument `search` as below, you can reference it with `self.config['pid']`
```python
requirements.StringRequirement(name = 'search',
                               description = "The string that you want to find"),
```
From what I see, the types of argument variables you can have are (not all there are):
```python
requirements.StringRequirement(name = "yara_rules", description = "Yara rules (as a string)", optional = True)
requirements.ListRequirement(name='pid', description='Filter on specific process IDs', element_type=int, optional=True)
requirements.BooleanRequirement(name = "insensitive", description = "Makes the search case insensitive", default = False, optional = True)
requirements.IntRequirement(name = "max_size", default = 0x40000000, description = "Set the maximum size (default is 1GB)", optional = True)
requirements.URIRequirement(name = "yara_file", description = "Yara rules (as a file)", optional = True) # This seems to be the same as StringRequirement
```

## run function
When you call a plugin using `vol`, it will call the run function of the particular plugin.

This function mainly does the UI portion of the output.
It does a return for a `TreeGrid` which requires a list of titles and a call to the \_generator function.
eg.

```python
def run(self):
    return renderers.TreeGrid([('Offset', format_hints.Hex), ('Rule', str), ('Component', str), ('Value', bytes)],
                               self._generator())
``` 

In each element of the list, you need to specify the title and the type of data you are dealing with.
Note that if you want it to display as hex you need to use the fomat_hints.Hex function to convert it to hex

## \_generator function

This function is the brain of the operation. Whatever you need to do is done here.

At the end of the function, you need to yield it as such
```
yield 0, (format_hints.Hex(offset), rule_name, name, value)
```
I have no idea what the 0 but after the 0 you need a tuple containing the data in the same order as you did on the run function

# Layers
This is probably the most important part of volatility.
Layer is the "address space" of the memory but you will need to give it context

What I mean is that you can either choose to use the address space of the entire memory or the address space of a process

## Kernel layer
There are two ways of how I've seen

first is through the kernel module
```python
@classmethod
def get_requirements(cls):
    return [
        requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                       architectures = ["Intel32", "Intel64"])
    ]

def _generator(self):
    kernel = self.context.modules[self.config['kernel']]
    kernel_layer = self.context.layers[kernel.layer_name]
```

The other is through the primary translation layer
```python
@classmethod
def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
    return [
        requirements.TranslationLayerRequirement(name = 'primary',
                                                 description = "Memory layer for the kernel",
                                                 architectures = ["Intel32", "Intel64"]),
    ]

def _generator(self):
    layer = self.context.layers[self.config['primary']]
```

## Process layer
This one has a bit more code as it relies on pslist to show us the list of processes then afterwards we reference the layer

```python
from volatility3.plugins.windows import pslist, vadinfo

@classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.VersionRequirement(name = 'pslist', component = pslist.PsList, version = (2, 0, 0)),
        ]

def _generator(self, procs):

    for proc in procs:
        proc_id = proc.UniqueProcessId
        proc_layer_name = proc.add_process_layer()

        proc_layer = context.layers[proc_layer_name]

# You need to supply generator with pslist.PsList.list_processes
def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        kernel = self.context.modules[self.config['kernel']]

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Start VPN", format_hints.Hex),
                                   ("End VPN", format_hints.Hex), ("Tag", str), ("Protection", str),
                                   ("CommitCharge", int), ("PrivateMemory", int), ("File output", str),
                                   ("Hexdump", format_hints.HexBytes), ("Disasm", interfaces.renderers.Disassembly)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = kernel.layer_name,
                                                                   symbol_table = kernel.symbol_table_name,
                                                                   filter_func = filter_func)))
```

## Scanning

Once you have a layer you are able to perform scanning.

All the need to do is do the following:
```python
layer.scan(context = self.context, scanner = myscanner)
```

There are there 3 built in scanners in volatility:
- BytesScanner (scans for one bytestring)
- MultiStringScanner (scans for a list of bytestrings)
- RegexScanner (scans for a regex)

### ByteScanner
```python
from volatility3.framework.layers import scanners

layer = context.layers[layer_name]
for address in layer.scan(
    context = self.context,
    scanner = scanners.BytesScanner(b"#")):
```

### MultiStringScanner
```python
from volatility3.framework.layers import scanners

needles = [
    b'\x08http',
    b'\x08file',
    b'\x08ftp',
    b'\x08chrome',
    b'\x08data',
    b'\x08about',
    b'\x01\x01http',
    b'\x01\x01file',
    b'\x01\x01ftp',
    b'\x01\x01chrome',
    b'\x01\x01data',
    b'\x01\x01about',
]

layer = context.layers[layer_name]
for address, pattern in layer.scan(
    context = self.context,
    scanners.MultiStringScanner(needles)
    )
```

### RegexScanner
```python
from volatility3.framework.layers import scanners

layer = context.layers[layer_name]
for address in layer.scan(
    context = context,
    scanner = scanners.RegExScanner(rb"(Linux version|Darwin Kernel Version) [0-9]+\.[0-9]+\.[0-9]+")):
```

### Own scanner
You can also build you own scanner

this is done by creating a class that inherits the `interfaces.layers.ScannerInterface`

```python
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
```


# Importing files
If you have a custom file that you want to import, you can't import it as such
```
import sqlite_helper
```
the way to import it for volatility is as such
```
import volatility3.plugins.sqlite_helper
```