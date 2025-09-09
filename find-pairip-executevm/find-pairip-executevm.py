import errno
import sys
import os.path
from pathlib import Path
from argparse import _ArgumentGroup, Namespace
from frida_fusion.libs.logger import Logger
from frida_fusion.module import ModuleBase
from frida_fusion.libs.scriptlocation import ScriptLocation
from frida_fusion.exceptions import SilentKillError


class FindPairip(ModuleBase):

    def __init__(self):
        super().__init__('Find Pairip ExecuteVM', 'Find Lib Pairip ExecuteVM address by Helvio Junior (M4v3r1ck)')
        self.mod_path = str(Path(__file__).resolve().parent)
        self._register_natives_offset = 0;
        self._suppress_messages = False
        self.js_file = os.path.join(self.mod_path, "find-pairip-executevm.js")

    def start_module(self, **kwargs) -> bool:
        pass

    def js_files(self) -> list:
        return [
            self.js_file
        ]

    def suppress_messages(self):
        self._suppress_messages = True

    def dynamic_script(self) -> str:
        return f"const RN_HOOK_OFFSET = {self._register_natives_offset};"
    
    def add_params(self, flags: _ArgumentGroup):
        flags.add_argument('--pairip-offset',
                         dest='pairip_offset',
                         metavar='pairip_offset',
                         default=None,
                         required=False,
                         type=str,
                         help='RegisterNatives function offset')

    def load_from_arguments(self, args: Namespace) -> bool:
        if args.pairip_offset is None:
            return True

        if len(args.pairip_offset) <= 4 or args.pairip_offset[0:2].lower() != "0x":
            Logger.pl('{!} {R}error: invalid offset value{O} %s{W}\r\n' % args.pairip_offset)
            return False

        self._register_natives_offset = int(args.pairip_offset, 16)
        return True

    def key_value_event(self,
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:


        if module == "libpairipcore.so!RegisterNatives":
            self._register_natives_offset = received_data.get('offset', 0)

            Logger.print_message(
                level="W",
                message=f"RegisterNatives offset: {self._register_natives_offset}",
                script_location=script_location
            )

            raise SilentKillError(message="{+} Run the frida-fusion again adding parameter {O}--pairip-offset %s{W}" % self._register_natives_offset)

        elif module == "libpairipcore.so!RegisterNatives!call!executeVM":
            desc = received_data.get('description', None)
            offset = received_data.get('offset', None)
            if desc is not None:
                Logger.print_message(
                    level="I",
                    message=f"{desc}\n",
                    script_location=script_location
                )
            
            if offset is not None:
                Logger.print_message(
                    level="W",
                    message=f"executeVM ghidra offset: {offset}",
                    script_location=script_location
                )

                raise SilentKillError()


        elif "libpairipcore.so" in module:
            Logger.print_message(
                    level="D",
                    message=f"Data received: {module}",
                    script_location=script_location
                )


        return True

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        return True


