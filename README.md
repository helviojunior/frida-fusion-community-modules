# Frida Fusion - Community logs

This repo is part of Frida Fusion tool [https://github.com/helviojunior/frida-fusion/](https://github.com/helviojunior/frida-fusion/)


## Using this modules

> :information_source: First install frida-fusion `pip3 install frida-fusion` package.

Using the community modules

```bash
cd /tmp/
git clone https://github.com/helviojunior/frida-fusion-community-modules
export FUSION_MODULES=/tmp/frida-fusion-community-modules

# List all modules
frida-fusion --list-modules
```

## Developing a new module

To develop a new module you just need to create a python file using this sample code:

```python
import errno
import os.path
from pathlib import Path
from frida_fusion.libs.logger import Logger
from frida_fusion.module import ModuleBase

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from frida_fusion.fusion import Fusion


class SampleModule(ModuleBase):

    def __init__(self):
        super().__init__('Sample module', 'Frida-fusion sample module')
        self.mod_path = str(Path(__file__).resolve().parent)

    def start_module(self, **kwargs) -> bool:
        Logger.pl("{+} Starting my first Frida Fusion module")

    def js_files(self) -> list:
        return []

    def key_value_event(self,
                        script_location: "Fusion.ScriptLocation" = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:
        return True

    def data_event(self,
                   script_location: "Fusion.ScriptLocation" = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        return True

```