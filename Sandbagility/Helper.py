import logging
import ctypes
import struct

from .Symbol import Symbol
from .Windows.ntoskrnl import Windows
from .Breakpoint import Breakpoint


class Helper():

    _LOGGER = 'Helper'

    def __init__(self, vmname, dbg, KernelPdbPath=None, KernelBaseAddress=0, debug=[]):

        logging.basicConfig(
            level=logging.INFO, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')

        self.debug = debug

        self.logger = logging.getLogger('{:20}'.format(self._LOGGER))
        if self._LOGGER in debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        # Init
        self.dbg = dbg(vmname)
        self.dbg.Pause()
        self.UnsetAllBreakpoints()

        self.os = Windows(self, debug)

        self.vmname = vmname

        # dictionnary: Address => Breakpoint Object
        self.breakpoints = {}

        self._cache = {}
        self.symbol = Symbol(debug=debug)

        self.modules = []
        self.modules.append(self.__load_kernel_symbol__())
        self.symbol.SymLoadModules(self.modules)

    def __load_kernel_symbol__(self):

        KernelBaseAddress, KernelImageSize = self.os.KeGetKernelInformation()
        KernelImage = self.MoDumpImage(
            KernelBaseAddress, ImageSize=KernelImageSize, Callback=lambda x: x.find(b'RSDS') != -1)

        RawData = KernelImage[KernelImage.find(b'RSDS'):]
        Rsds = self.os.MoParseRsdsRawData(RawData)
        if Rsds is None:
            raise Exception('HelperError: cannot find kernel symbol')

        KernelPdbPath = self.symbol.SymGetModulePdbPath(Rsds)
        self.logger.debug('Kernel PDB path : %s' % KernelPdbPath)

        return (KernelPdbPath, KernelBaseAddress, KernelImageSize)

    def ResetCache(self):
        self._cache = {}

    def Run(self):
        '''
        @brief This function execute the virtual machine and execute each
        handler registered for each breakpoint
        '''
        while True:

            self.ResetCache()
            self.dbg.Resume()
            self.dbg.WaitBreak()
            if self.BreakpointDispatchHandler():
                continue
            else:
                break

    def SwapContext(self, ProcessName, Userland=True):
        '''
            @brief This function perform a switch of context and return as soon
            as the new context is found
        '''

        UserReturn = None
        BreakpointId = self.dbg.SetControlRegisterBreakpoint(3, 'r')
        self.add_breakpoint(None, None, BreakpointId, None)

        while True:

            self.Run()

            ActiveProcess = self.PsGetCurrentProcess()

            if ActiveProcess == ProcessName:
                if Userland is False:
                    break
                elif hasattr(ActiveProcess.Thread, 'TrapFrame') and \
                        (ActiveProcess.Thread.TrapFrame.Rip & 0xffff000000000000) == 0:
                    UserReturn = ActiveProcess.Thread.TrapFrame.Rip
                    break

        self.unset_breakpoint(None, None, None)

        if Userland and UserReturn is not None:
            self.logger.debug(
                "SwapContext:ActiveProcess.UserReturn: %x", UserReturn)

            BreakpointId = self.SetBreakpoint(
                UserReturn, cr3=ActiveProcess.DirectoryTableBase)
            self.logger.debug(
                "SwapContext:SetBreakpoint: BreakpointId: %x", BreakpointId)

            self.Run()
            self.UnsetBreakpoint(UserReturn, ActiveProcess.DirectoryTableBase)

            return ActiveProcess
        elif Userland and UserReturn is None:
            return None
        else:
            return ActiveProcess

    def UnsetAllBreakpoints(self):

        self.dbg.UnsetAllBreakpoint()
        self.dbg.UnsetBreakpointHardware()

    def run_to(self, Address, Cr3=None):
        '''
            execute until the given address is reached
        '''

        BpId = self.dbg.AddBreakpoint(Address, 0, Cr3)

        while(True):
            self.dbg.Resume()
            self.dbg.WaitBreak()

            if Cr3 is None and Address == self.dbg.rip:
                break
            elif Address == self.dbg.rip and Cr3 == self.dbg.cr3:
                break
            else:
                continue

        # Check if the BpId exist for someone else
        # ID = target
        for addr in self.breakpoints:
            for item in self.breakpoints[addr].breakpoints.values():
                if item['id'] == BpId:
                    return

        self.dbg.UnsetBreakpoint(BpId)

    def unset_breakpoint(self, address, cr3, handler):

        ID = self.breakpoints[address].delete_breakpoint(cr3, handler)
        self.logger.debug("Unset breakpoint %s at %s", ID, address)

        if self.breakpoints[address].is_empty():
            self.breakpoints.pop(address)
            """ Do not remove hardware breakpoint """
            if ID != 254:
                self.dbg.UnsetBreakpoint(ID)

        return ID

    def UnsetBreakpoint(self, target, cr3=None, handler=None):

        if isinstance(target, str):
            address = self.SymLookupByName(target)
            if address is None:
                self.logger.warning("Symbol %s not found", target)
                return None
            ID = self.breakpoints[address].get_ID(cr3)

        elif isinstance(target, int):
            if target < 255:  # may-be a ID
                raise Exception('Shutup')
                ID = target
                for addr in self.breakpoints:
                    cr3 = self.breakpoints[addr].get_cr3_by_ID(ID)
                    if cr3:
                        address = addr
                        break

            else:
                # target is an address
                address = target
                ID = self.breakpoints[address].get_ID(cr3)

        return self.unset_breakpoint(address, cr3, handler)

    def UnsetBreakpointByCr3(self, cr3):

        for address in self.breakpoints.copy():
            breakpoint = self.breakpoints[address]
            if breakpoint.exists(cr3):
                for handler in breakpoint.get_handler(cr3):
                    self.UnsetBreakpoint(address, cr3, handler)

    def UnsetHardwareBreakpoint(self, BpId, Cr3):
        return self.UnsetBreakpoint(BpId, Cr3)

    def __lookup_target_into_address__(self, target, description=''):

        if isinstance(target, str):
            # set bp by symbol name
            address = self.SymLookupByName(target)
            if address is None:
                self.logger.warning("Symbol %s not found", target)
                return None
        if isinstance(target, int):
            # set bp by address
            address = target

        return address

    def SetBreakpoint(self, target, handler=None, cr3=None, description=''):

        address = self.__lookup_target_into_address__(target)
        if address is None:
            raise Exception('SetBreakpointError: cannot resolve %s' % target)

        if (address in self.breakpoints):

            breakpoint = self.breakpoints[address]

            if breakpoint.exists(cr3):

                if handler in breakpoint.get_handler(cr3):
                    return breakpoint.get_ID(cr3)
                else:
                    breakpoint.set_handler(cr3, handler)
                    return breakpoint.get_ID(cr3)

            AnyCr3 = list(breakpoint.breakpoints.keys())[0]
            BpId = breakpoint.get_ID(AnyCr3)

        else:

            BpId = self.dbg.AddBreakpoint(address, 0, None)
            if BpId == 255:
                return BpId
                # self.logger.error('Cannot set breakpoint %x at address %x on cr3 %s', BpId, address, str(cr3))
               # raise Exception('BreakpointError: Cannot set breakpoint %x at address %x on cr3 %s', BpId, address, str(cr3))

        BpId = self.add_breakpoint(
            address, handler, BpId, cr3, description=description)

        return BpId

    def add_breakpoint(self, address, handler, BpId, cr3, description=''):

        if address in self.breakpoints.keys():
            if self.breakpoints[address].exists(cr3):
                # update handler
                ID = self.breakpoints[address].update_breakpoint(
                    BpId, handler, cr3)
                # self.logger.debug("Update breakpoint %s", ID)

            else:
                ID = self.breakpoints[address].add_breakpoint(
                    BpId, handler, cr3)
                # self.logger.debug("Add breakpoint %s", ID)

            return ID
        else:
            # add new breakpoint
            breakpoint = Breakpoint(
                address, BpId, handler, cr3, description=description)
            self.breakpoints[address] = breakpoint
            # self.logger.debug("Create breakpoint %x at %x", BpId, address)

            return BpId

    def SetHardwareBreakpoint(self, target, access, handler, dr=0, cr3=None):

        address = self.__lookup_target_into_address__(target)
        if address is None: 
            self.logger.warning('SetBreakpointError: cannot resolve %s on dr%d' % (target, dr))
            return None
            #raise Exception('SetBreakpointError: cannot resolve %s' % target)

        # self.logger.warning('Set hardware breakpoint register %d with %s' % (dr, target))

        self.dbg.SetBreakpointHardware(address, dr=dr, access=access, length=1)
        return self.add_breakpoint(address, handler, BpId=254, cr3=cr3)

    def SetMemoryBreakpoint(self, Target, RegionSize, Handler, Protect='e', cr3=None):

        BaseAddress = self.__lookup_target_into_address__(Target)

        BpId = self.dbg.SetMemoryBreakpoint(
            BaseAddress, RegionSize, Protect, cr3=cr3)
        if BpId == 255:
            raise Exception('SetMemoryBreakpointError: %d' % BpId)

        return self.add_breakpoint((BaseAddress, RegionSize), Handler, BpId=BpId, cr3=cr3)

    def BreakpointDispatchHandler(self):

        bContinue = True
        current_address = self.dbg.rip
        breakpoint = None

        self.logger.debug('[?] Breakpoint Hit: Rip: %.16x, Cr3: %.16x, Process: %s',
                          current_address, self.dbg.cr3, self.PsGetCurrentProcess().ImageFileName)

        '''
        If None has been set as a target address, then the dispatcher will
        stop at each breakpoint hit
        '''
        if None in self.breakpoints:
            return False

        if current_address in self.breakpoints:
            breakpoint = self.breakpoints[current_address]
        else:
            for BaseAddress, RegionSize in [membp for membp in self.breakpoints if isinstance(membp, tuple)]:
                if BaseAddress < current_address < (BaseAddress + RegionSize):
                    breakpoint = self.breakpoints[(BaseAddress, RegionSize)]
                    break

        if breakpoint is None:
            '''
                BreakpointDispatchHandlerWarning: A breakpoint at current rip for
                a previous set breakpoint was reached, but there is no handler 
                anymore...'
            '''
            return True

        cr3 = self.dbg.cr3

        if breakpoint.exists(cr3):
            h = breakpoint.get_handler(cr3)

        elif breakpoint.exists(None) and breakpoint.get_handler(None) is not None:
            h = breakpoint.get_handler(None)
        else:
            return True

        status = []

        if h is None:
            return False
        for _ in h.copy():

            """ If no handler is given, then the dispatcher is interrupted """
            if _ is not None:
                status.append(_())
            else:
                status.append(False)

            self.logger.debug('[*] Breakpoint Hit: Rip: %.16x, Cr3: %.16x, Process: %s, Description: %s, Handler: %s',
                              current_address, cr3, self.PsGetCurrentProcess().ImageFileName, breakpoint.description, _)

        if False in status:
            return False
        return True

    def GetStructureMemberAddress(self, VirtualAddress, StructureName, MemberName):
        if VirtualAddress is None:
            return None
        return (VirtualAddress + self.symbol.GetStructureMemberOffset(StructureName, MemberName))

    def ReadStructure(self, VirtualAddress, Type):

        if VirtualAddress is None:
            return None

        if isinstance(Type, str):
            Structure = self.symbol.PdbToCTypes(Type)
        elif isinstance(Type, type(ctypes.Structure)):
            Structure = Type
        else:
            raise Exception(
                'StructureTypeError: Invalid instance for structure : %s' % type(Type))

        if isinstance(VirtualAddress, int):
            Value = self.ReadVirtualMemory(
                VirtualAddress, ctypes.sizeof(Structure))
            if Value is None:
                return None

            Data = Structure.from_buffer_copy(Value)
            return Data
        else:
            try:
                VirtualAddress = bytes(VirtualAddress)
            except:
                raise Exception('HelperError: Cannot convert %s to %s' % (
                    type(VirtualAddress), bytes))

            if isinstance(VirtualAddress, bytes):
                Data = Structure.from_buffer_copy(VirtualAddress)
                return Data

    def ReadStructureMember(self, VirtualAddress, StructureName, MemberName, ReadSize):
        if VirtualAddress is None:
            return None
        Address = self.GetStructureMemberAddress(
            VirtualAddress, StructureName, MemberName)
        return self.dbg.ReadVirtualMemory(Address, ReadSize)

    def ReadStructureMember64(self, VirtualAddress, StructureName, MemberName):
        Value64 = self.ReadStructureMember(
            VirtualAddress, StructureName, MemberName, 8)
        if Value64 is None:
            return None
        return struct.unpack('<Q', Value64)[0]

    def ReadStructureMember32(self, VirtualAddress, StructureName, MemberName):
        Value32 = self.ReadStructureMember(
            VirtualAddress, StructureName, MemberName, 4)
        if Value32 is None:
            return None
        return struct.unpack('<L', Value32)[0]

    def ReadStructureMember16(self, VirtualAddress, StructureName, MemberName):
        Value16 = self.ReadStructureMember(
            VirtualAddress, StructureName, MemberName, 2)
        if Value16 is None:
            return None
        return struct.unpack('<H', Value16)[0]

    def ReadStructureMember8(self, VirtualAddress, StructureName, MemberName):
        Value8 = self.ReadStructureMember(
            VirtualAddress, StructureName, MemberName, 1)
        if Value8 is None:
            return None
        return struct.unpack('<B', Value8)[0]

    def ReadVirtualMemory(self, Input, Size, Lazy=False):

        PAGE_SIZE = 0x1000

        if Size == 0: return None
        
        if isinstance(Input, int): VirtualAddress = Input
        elif isinstance(Input, str): VirtualAddress = self.SymLookupByName(Input)
        else: return None

        Data = self.dbg.ReadVirtualMemory(VirtualAddress, Size)

        if Data is None:

            Data = b''

            for PageAddress in range(((VirtualAddress >> 0xc) << 0xc), VirtualAddress + Size, PAGE_SIZE):

                Chunk = self.dbg.ReadVirtualMemory(PageAddress, PAGE_SIZE)
                if Chunk is None:

                    if (self.dbg.cs & 0x3) == 3:

                        self.dbg.InjectInterrupt(0xE, 00, PageAddress)
                        self.run_to(self.dbg.rip, self.dbg.cr3)
                        Chunk = self.dbg.ReadVirtualMemory(PageAddress, PAGE_SIZE)

                        if Chunk is None:
                            ''' In Lazy mode, the ReadVirtualMemory does a best
                            effort read until a page is not readable
                            '''
                            if Lazy and Data: return Data
                            
                            return None

                    else:
                        if Lazy and Data: return Data
                        return None

                Data += Chunk

            StartOffset = VirtualAddress - ((VirtualAddress >> 0xc) << 0xc)
            Data = Data[StartOffset:StartOffset + Size]

        return Data

    def ReadVirtualMemory8(self, VirtualAddress, CpuId=0):
        Value = self.dbg.ReadVirtualMemory(VirtualAddress, 1, CpuId)
        if Value is None:
            return None
        return struct.unpack('<B', Value)[0]

    def ReadVirtualMemory16(self, VirtualAddress, CpuId=0):
        Value = self.dbg.ReadVirtualMemory(VirtualAddress, 2, CpuId)
        if Value is None:
            return None
        return struct.unpack('<H', Value)[0]

    def ReadVirtualMemory32(self, VirtualAddress, CpuId=0):
        Value32 = self.dbg.ReadVirtualMemory(VirtualAddress, 4, CpuId)
        if Value32 is None:
            return None
        return struct.unpack('<L', Value32)[0]

    def ReadVirtualMemory64(self, VirtualAddress, CpuId=0):
        Value64 = self.dbg.ReadVirtualMemory(VirtualAddress, 8, CpuId)
        if Value64 is None:
            return None
        return struct.unpack('<Q', Value64)[0]

    def WriteVirtualMemory(self, VirtualAddress, Value):
        return self.dbg.WriteVirtualMemory(VirtualAddress, Value)

    def WriteVirtualMemory64(self, VirtualAddress, Value, CpuId=0):
        Value64 = struct.pack('<Q', Value)
        return self.dbg.WriteVirtualMemory(VirtualAddress, Value64, CpuId)

    def ReadUnicodeString(self, *args, **kwargs):
        return self.os.ReadUnicodeString(*args, **kwargs)

    def ReadCString(self, address, size=260, Ansi=True, PageOut=False):

        if address == 0:
            return None

        if Ansi:
            max_length = size
        else:
            max_length = size * 2

        if Ansi is True:
            """Return ascii string (optional maximum size of the string) """
            data = self.ReadVirtualMemory(address, max_length)
            if data is None and PageOut is False:
                return None
            elif data is None and PageOut is True:
                data = self.os.MoDumpImage(address, ImageSize=max_length)

            bstring = data.split(b'\x00', 2)[0]
            return bstring.decode('ascii')
        else:
            """Return utf16 string (optional maximum size of the string) """
            data = self.ReadVirtualMemory(address, max_length)
            if data is None:
                return ''

            idx = data.find(b'\x00\x00')
            if idx == -1:
                idx = size
            if idx % 2 != 0:
                idx += 1
            try: return data[:idx].decode('utf-16')
            except: return None

    def PsEnumLoadedModule(self, *args, **kwargs):
        return self.os.PsEnumLoadedModule(*args, **kwargs)

    def PsEnumProcesses(self, *args, **kwargs):
        return self.os.PsEnumProcesses(*args, **kwargs)

    def PsGetCurrentProcess(self, *args, **kwargs):

        if 'PsGetCurrentProcess' not in self._cache:
            ''' If the current process is not in cache, then retrieve process information
                with the given parameters into the cache
            '''
            self._cache['PsGetCurrentProcess'] = (
                self.os.PsGetCurrentProcess(*args, **kwargs), args, kwargs)

        else:
            ''' If the current process information is already in the cache, check if the parameters
            still the same, otherwise update the current process information
            '''
            ActiveProcess, _args, _kwargs = self._cache['PsGetCurrentProcess']
            if args != _args or kwargs != _kwargs:
                self._cache['PsGetCurrentProcess'] = (
                    self.os.PsGetCurrentProcess(*args, **kwargs), args, kwargs)

        ''' Return the current process information from the cache
        '''
        return self._cache['PsGetCurrentProcess'][0]

    def PsGetCurrentThread(self, *args, **kwargs):
        return self.os.PsGetCurrentThread(*args, **kwargs)

    def PsLookupProcessByProcessId(self, *args, **kwargs):
        return self.os.PsLookupProcessByProcessId(*args, **kwargs)

    def PsLookupProcessByProcessName(self, *args, **kwargs):
        return self.os.PsLookupProcessByProcessName(*args, **kwargs)

    def KeGetKernelBaseAddress(self, *args, **kwargs):
        return self.os.KeGetKernelBaseAddress(*args, **kwargs)

    def KeGetGsVirtualAddress(self, *args, **kwargs):
        return self.os.KeGetGsVirtualAddress(*args, **kwargs)

    def MoGetImageSize(self, *args, **kwargs):
        return self.os.MoGetImageSize(*args, **kwargs)

    def MoGetEntryPoint(self, *args, **kwargs):
        return self.os.MoGetEntryPoint(*args, **kwargs)

    def MoIsAddressMapped(self, *args, **kwargs):
        return self.os.MoIsAddressMapped(*args, **kwargs)

    def MoDumpImage(self, *args, **kwargs):
        return self.os.MoDumpImage(*args, **kwargs)

    def MoGetDebugInformation(self, *args, **kwargs):
        return self.os.MoGetRsdsDebugInformation(*args, **kwargs)

    def MoGetModuleByName(self, module, Process=None):

        if Process is None: ActiveProcess = self.PsGetCurrentProcess(loadLdr=True)
        else: ActiveProcess = Process

        if ActiveProcess.WoW64Process and ActiveProcess.LdrData32:
            for Module in ActiveProcess.LdrData32.Modules:
                if module in Module.FullDllName:
                    return Module

        if ActiveProcess.LdrData:
            for Module in ActiveProcess.LdrData.Modules:
                if module in Module.FullDllName:
                    return Module

        for Module in self.PsEnumLoadedModule():
            if module in Module.DriverName:
                return Module

        return None

    def SymGetModulePdbPath(self, Module):

        if isinstance(Module, int):
            Address = Module
            Module = self.MoDumpImage(
                Address, Callback=lambda x: x.find(b'RSDS') != -1)

        return self.symbol.SymGetModulePdbPath(Module)

    def SymReloadModule(self, ImageBase, ImageSize=0):

        self.logger.debug('SymReloadModule: Rip: %x', self.dbg.rip)
        self.logger.debug(
            'SymReloadModule: ImageBase: %x, ImageSize: %x', ImageBase, ImageSize)

        if not ImageSize:
            ImageSize = self.MoGetImageSize(ImageBase)

        for name, info in self.symbol.loaded_modules.items():
            if info['Base'] == ImageBase and info['Size'] == ImageSize:
                return True

        Rsds = self.MoGetDebugInformation(ImageBase)
        if Rsds is None:
            return False

        PdbPath = self.symbol.SymGetModulePdbPath(Rsds)
        if PdbPath is None:
            return False

        self.logger.debug('SymReloadModule: %s', PdbPath)
        self.symbol.SymLoadModules([(PdbPath, ImageBase, ImageSize)])

        return True

    def SymReloadUserModule(self, ModuleList=[]):

        LoadedModuleCount = 0

        ActiveProcess = self.PsGetCurrentProcess(loadLdr=True)

        if ActiveProcess.WoW64Process and ActiveProcess.LdrData32:
            for Module in ActiveProcess.LdrData32.Modules:
                if ModuleList == []:
                    Status = self.SymReloadModule(Module.DllBase, Module.SizeOfImage)
                elif True in [ModuleName in Module.FullDllName for ModuleName in ModuleList]:

                    Cache = self.symbol.SymGetLoadedModuleByAddress(
                        Module.DllBase)

                    if Cache is None:
                        Status = self.SymReloadModule(Module.DllBase, Module.SizeOfImage)
                    else:
                        Status = True

                    if Status:
                        LoadedModuleCount += 1
                    if LoadedModuleCount == len(ModuleList):
                        return True

        elif not ActiveProcess.WoW64Process and ActiveProcess.LdrData:
            for Module in ActiveProcess.LdrData.Modules:
                if ModuleList == []:
                        Status = self.SymReloadModule(Module.DllBase, Module.SizeOfImage)
                elif True in [ModuleName in Module.FullDllName for ModuleName in ModuleList]:

                    Cache = self.symbol.SymGetLoadedModuleByAddress(Module.DllBase)

                    if Cache is None:
                        Status = self.SymReloadModule(Module.DllBase, Module.SizeOfImage)
                    else:
                        Status = True

                    if Status:
                        LoadedModuleCount += 1
                    if LoadedModuleCount == len(ModuleList):
                        return True

        if not ModuleList:
            return True
        elif LoadedModuleCount == len(ModuleList):
            return True
        else:
            return False

    def SymReloadKernelModule(self, ModuleList=[]):

        Status = False
        LoadedModuleCount = 0

        for module in self.PsEnumLoadedModule():
            if module.DriverName not in ModuleList:
                continue

            Module = self.symbol.SymGetLoadedModuleByAddress(module.ImageBase)

            if Module is None:

                DebugInformation = self.MoGetDebugInformation(module.ImageBase)
                if DebugInformation is None:
                    continue

                PdbPath = self.SymGetModulePdbPath(DebugInformation)
                if PdbPath is None:
                    continue

                self.symbol.SymLoadModules(
                    [(PdbPath, module.ImageBase, module.ImageSize)])

            LoadedModuleCount += 1
            if LoadedModuleCount == len(ModuleList):
                return True

        return Status

    def SymIsAddressInUserModule(self, Module, Address):
        if hasattr(Module, 'DllBase'):
            if Module.DllBase <= Address <= (Module.DllBase + Module.SizeOfImage):
                return True
            return False
        elif hasattr(Module, 'ImageBase'):
            if Module.ImageBase < Address < (Module.ImageBase + Module.ImageSize):
                return True
            return False

    def SymGetUserModuleByAddress(self, Address, Process=None):

        if Process is None: Process = self.PsGetCurrentProcess(loadLdr=True)

        if Process.WoW64Process and Process.LdrData32:
            for Module in Process.LdrData32.Modules:
                if not self.SymIsAddressInUserModule(Module, Address):
                    continue
                return Module

        elif not Process.WoW64Process and Process.LdrData:
            for Module in Process.LdrData.Modules:
                if not self.SymIsAddressInUserModule(Module, Address):
                    continue
                return Module

        return None

    def SymGetUserModuleNameByAddress(self, Address, Process=None):

        Module = self.SymGetUserModuleByAddress(Address, Process=Process)
        if Module is None: return None

        return str(Module.FullDllName)

    def SymGetKernelModuleByAddress(self, Address):

        Module = self.symbol.SymGetLoadedModuleByAddress(Address)
        if Module is not None: return Module

        for Module in self.PsEnumLoadedModule():
            if not self.SymIsAddressInUserModule(Module, Address):
                continue
            return Module

        return None

    def SymLookupByAddress(self, Address, Process=None):

        if Process is None: Process = self.PsGetCurrentProcess(loadLdr=True)

        if not (Address & 0xfff0000000000000):
            Module = self.SymGetUserModuleByAddress(Address=Address, Process=Process)
            if Module is None: return None
            ImageBase = Module.DllBase
        else:
            ''' TODO Create module class to make use of module more
            consistent between modules from userland, kernelland and symbol 
            '''
            Module = self.SymGetKernelModuleByAddress(Address=Address)
            if Module is None: return None
            elif isinstance(Module, dict): ImageBase = Module['Base']
            elif hasattr(Module, 'ImageBase'): ImageBase = Module.ImageBase
            else: return None

        if not self.SymReloadModule(ImageBase): 
            return None

        return self.symbol.LookupByAddr(Address)

    def SymLookupByName(self, Symbol, Process=None):

        if Process is None: Process = self.PsGetCurrentProcess(loadLdr=True)

        if Symbol.find('!') != -1:
            Module = self.MoGetModuleByName(Symbol.split('!')[0])
            if Module is None: return None

            if hasattr(Module, 'DllBase'): ImageBase = Module.DllBase
            elif hasattr(Module, 'ImageBase'): ImageBase = Module.ImageBase
            else: return None

            if not self.SymReloadModule(ImageBase):
                return None

        return self.symbol.LookupByName(Symbol)