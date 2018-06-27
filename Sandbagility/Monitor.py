import os
import time
import logging

from abc import ABC, abstractmethod

MONITOR_MODE_SUPERVISOR = 0
MONITOR_MODE_USER = 1

class dummy():
    def __repr__(self):
        d = self.__dict__.copy()
        if 'helper' in d:
            del d['helper']
        if 'logger' in d:
            del d['logger']
        return str(d)


class Operation(dummy):

    def __init__(self, Info=None):
        self.isEmpty = True

    def __save__(self, *args, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def Save(self, *args, **kwargs):
        self.__save__(*args, **kwargs)
        self.isEmpty = False

    def Copy(self):
        n = Operation()
        n.__dict__ = self.__dict__.copy()

        return n


class Monitor():

    _NAME = None
    _DEPENDENCIES = None

    class Parameters(dummy):
        pass

        def __str__(self): return '%s' % self.__dict__

    @property
    def Dependencies(self):
        return [ d.lower() for d in self._DEPENDENCIES ]

    @property
    def ActiveProcess(self):
        return self.helper.PsGetCurrentProcess(loadLdr=False)

    @property
    def Name(self): return self._NAME

    @Name.setter
    def Name(self, value): self._NAME = value

    @property
    def Cache(self): return self._cache[self._NAME]

    @Cache.setter
    def Cache(self, value): self._cache[self._NAME] = value

    def __init__(self, helper, Process=None, mode=MONITOR_MODE_USER, verbose=False):

        self._cache = {}
        self._cache[self._NAME] = {}

        self.helper = helper
        self.mode = mode
        self.Process = Process

        if Process is not None:
            self.cr3 = Process.DirectoryTableBase
        else:
            self.cr3 = None

        self.PreCallbacks = []
        self.PostCallbacks = []
        self.Results = []
        self.LastOperation = Operation()

        self.__init_logger__(verbose=verbose)

        if hasattr(self, '__pre__'):
            self.RegisterPreCallback(self.__pre__)
        if hasattr(self, '__post__'):
            self.RegisterPostCallback(self.__post__)

    def __install__(self, *args, **kwargs): pass

    def __init_logger__(self, verbose):

        self.logger = logging.getLogger('{:<20}'.format(self._NAME))
        if self._NAME in self.helper.debug:
            self.logger.setLevel(logging.DEBUG)

        else:
            self.logger.setLevel(logging.INFO)

        if verbose:
            self.EnableInfoLog()
        else:
            self.DisableInfoLog()

    def __eq__(self, other):
        if isinstance(other, str):
            return self._NAME == other

    def __ne__(self, other):
        return not self.__eq__(other)

    def LookupByName(self, symbol):

        if symbol not in self._cache:
            address = self.helper.symbol.LookupByName(symbol)
            self._cache[symbol] = address
            self._cache[address] = symbol

        return self._cache[symbol]

    def LookupByAddr(self, Address):
        
        if Address not in self._cache:
            Symbol = self.helper.SymLookupByAddress(Address)
            if Symbol is None: 
                print(Address, Symbol)
                return ''
            
            self._cache[Address] = Symbol
        
        return self._cache[Address] 

    def DisableInfoLog(self): self.EnableInfoLog = False

    def EnableInfoLog(self): self.EnableInfoLog = True

    def SetBreakpoint(self, target, handler):

        if isinstance(target, str):
            address = self.LookupByName(target)
            description = target
        else:
            address = target
            description = ''
        return self.helper.SetBreakpoint(address, handler, self.cr3, description=description)

    def SetHardwareBreakpoint(self, target, handler, dr=0, description=''):

        if isinstance(target, str):
            address = self.LookupByName(target)
            description = target
        else:
            address = target
            description = description

        return self.helper.SetHardwareBreakpoint(target, 'e', handler, dr=dr, cr3=self.cr3)

    @abstractmethod
    def NotifyLoadImage(self, Process, NotifyLoadImage):
        pass

    def RegisterPreCallback(self, pfnCallback):
        if pfnCallback not in self.PreCallbacks:
            self.PreCallbacks.append(pfnCallback)

    def UnregisterPreCallback(self, pfnCallback):
        if pfnCallback not in self.PreCallbacks:
            return
        self.PreCallbacks.remove(pfnCallback)

    def RegisterPostCallback(self, pfnCallback):
        if pfnCallback not in self.PostCallbacks:
            self.PostCallbacks.append(pfnCallback)

    def UnregisterPostCallback(self, pfnCallback):
        if pfnCallback not in self.PostCallbacks:
            return
        self.PostCallbacks.remove(pfnCallback)

    def ReadVirtualMemoryPointer(self, VirtualAddress):
        if self.ActiveProcess.WoW64Process:
            return self.helper.ReadVirtualMemory32(VirtualAddress)
        else:
            return self.helper.ReadVirtualMemory64(VirtualAddress)

    def GetStackValueByIndex(self, Index):
        '''
            @brief Read a stack value by its index depending on the architecture
            of the process
        '''
        if self.mode == MONITOR_MODE_USER and self.ActiveProcess.WoW64Process:
            return self.helper.ReadVirtualMemory32(self.StackPointer + Index * self.PointerSize)

        else:
            return self.helper.ReadVirtualMemory64(self.StackPointer + Index * self.PointerSize)

    def GetParameterByIndex(self, Index):
        '''
            @brief Return the parameter passed to the function based
            of the process architecture
            @remark The first parameter start at index = 0
        '''
        if self.mode == MONITOR_MODE_USER and self.ActiveProcess.WoW64Process:
            return self.GetStackValueByIndex(Index + 1)
        else:
            if Index == 0:
                return self.helper.dbg.rcx
            elif Index == 1:
                return self.helper.dbg.rdx
            elif Index == 2:
                return self.helper.dbg.r8
            elif Index == 3:
                return self.helper.dbg.r9
            elif Index >= 4:
                return self.GetStackValueByIndex(Index + 1)
            else:
                return None

    def PsGetReturnValue(self):

        class RunToHandler():
            def __init__(self, monitor, process):
                self.monitor = monitor
                self.Process = process

            def __call__(self):
                if self.Process.Cid != self.monitor.ActiveProcess.Cid:
                    return True

                self.monitor.helper.UnsetBreakpoint(
                    self.monitor.helper.dbg.rip, self.Process.DirectoryTableBase, self)
                self.Return = self.monitor.helper.dbg.rax
                return False

        ReturnAddress = self.GetStackValueByIndex(0)

        o = RunToHandler(self, self.ActiveProcess)
        o.BpId = self.helper.SetBreakpoint(
            ReturnAddress, o, cr3=self.ActiveProcess.DirectoryTableBase, description='PsGetReturnValue')
        self.helper.Run()

        if hasattr(o, 'Return'):
            return o.Return
        return None

    def SwapArgsValue(self, args, Name, Value):
        i = args.index(Name)
        args.remove(Name)
        args.insert(i, Value)

    def PrintInfoLog(self):

        if self.LastOperation.isEmpty:
            return

        self.logger.info(
            '{:<30}: Process: {:<20}, Cid: {:>10}, {}'.format(
                self.LastOperation.Action, self.LastOperation.Process.ImageFileName, str(
                    self.LastOperation.Process.Cid), repr(self.LastOperation.Detail)
            )
        )

    def _decorator(func, *args, **kwargs):
        def _decorator_internal(self, *args, **kwargs):

            self.LastOperation.isEmpty = True

            if self.PreCallbacks:
                for cb in self.PreCallbacks:
                    if cb(self, *args, **kwargs):
                        Status = func(self, *args, **kwargs)
                    else:
                        return True
            else:

                StartTimestamp = time.time()
                Status = func(self, *args, **kwargs)

                if not self.LastOperation.isEmpty:
                    self.LastOperation.Save(StartTimestamp=StartTimestamp, StopTimestamp=time.time())

            if not self.PostCallbacks:
                pass
            elif not self.LastOperation.isEmpty:
                for cb in self.PostCallbacks:
                    if cb(self, *args, **kwargs) == False:
                        return False

            if self.EnableInfoLog:
                self.PrintInfoLog()

            return Status

        return _decorator_internal


class KernelMonitor(Monitor):

    @property
    def PointerSize(self):
        return 8

    @property
    def StackPointer(self):
        return self.helper.dbg.rsp

    def __init__(self, helper, Process=None, verbose=False):

        super().__init__(helper, Process=Process,
                         mode=MONITOR_MODE_SUPERVISOR, verbose=verbose)

        self.Installed = False

        if self.Dependencies != None:
            Status = self.helper.SymReloadKernelModule(self.Dependencies)

            if Status and hasattr(self, '__install__'):

                if self.__install__() == True:
                    self.Installed = True

    def ReadParameters(self, Prototype, Callback=None):

        ParsedData = self.Parameters()

        for Index in range(len(Prototype)):

            fp = Prototype[Index]
            Value = self.GetParameterByIndex(Index)

            Name = fp.Name
            setattr(ParsedData, Name, Value)

            if not fp.IsInput and not fp.IsReturn:
                continue
            if fp.IsReturn:
                Value = self.PsGetReturnValue()

            if Value and Callback:
                Value = Callback(ParsedData, fp, Value)

            setattr(ParsedData, Name, Value)

        return ParsedData

class KernelGenericMonitor(KernelMonitor):

    def SetBreakpoint(self, target):
        return KernelMonitor.SetBreakpoint(self, target, self.__generic_handler__)

    def SetHardwareBreakpoint(self, target, dr=0):
        return super().SetHardwareBreakpoint(target, self.__generic_handler__, dr=dr)

    def __get_function_name__(self):

        FunctionName = self.LookupByAddr(self.helper.dbg.rip)
        if FunctionName.find('!') != -1:
            Module, FunctionName = FunctionName.split('!')

        if hasattr(self, '__get_canonical_function_name__'):
            FunctionName = self.__get_canonical_function_name__(FunctionName)

        return FunctionName

    def __post_process_parameters__(self, Parameters, Prototype):

        for Key, Value in Parameters.__dict__.items():
            if Key not in [p.Name for p in Prototype]:
                continue
            Proto = [p for p in Prototype if p.Name == Key][0]

            if not Proto.IsOutput:
                continue
            if Proto.IsPointer:
                Value = self.ReadVirtualMemoryPointer(Value)

            setattr(Parameters, Key, self.__pre_process_parameters__(
                Parameters, Proto, Value))

    def __pre_process_parameters__(self, Paramters, Proto, Value):

        if Value is None:
            return None

        if Proto.Type == 'OBJECT_ATTRIBUTES' and Proto.IsPointer:
            ObjectAttributes = self.helper.ReadStructure(
                Value, 'nt!_OBJECT_ATTRIBUTES')
            Paramters.ObjectName = self.helper.ReadUnicodeString(
                ObjectAttributes.ObjectName)
        elif Proto.Type == 'HANDLE' and not Proto.IsPointer:
            if Value == 18446744073709551615:  # -1 for current process
                pass
            #     Value = 'CurrentProcess'
            elif Value == 18446744073709551614:  # -2 for current thread
                pass
            #     Value = 'CurrentThread'
            elif Value == 18446744073709551610: pass
            #     Value = 'CurrentToken__'
            else:
                Paramters.Object = self.ActiveProcess.ObReferenceObjectByHandle(
                    Value)
        elif Proto.Type in ['DWORD', 'ULONG', 'LONG']:
            Value &= 0xffffffff
        elif Proto.Type == 'WORD':
            Value &= 0xffff
        elif Proto.Type == 'BYTE':
            Value &= 0xFF
        elif Proto.Type == 'BOOL':
            Value &= 0x1

        return Value

    @KernelMonitor._decorator
    def __generic_handler__(self):
        '''
            @brief Monitor callback for each OpenService event
        '''
        self.FunctionName = self.__get_function_name__()

        Prototype = self.helper.symbol.SymGetSyscallPrototype(self.FunctionName)
        Parameters = self.ReadParameters(Prototype, Callback=self.__pre_process_parameters__)

        if hasattr(self, '__post_process_parameters__'):
            self.__post_process_parameters__(Parameters, Prototype)

        self.LastOperation.Save(Action=self.FunctionName,
                                Process=self.ActiveProcess, Detail=Parameters)

        return True


class UserlandMonitor(Monitor):

    @property
    def PointerSize(self):

        if 'PointerSize' not in self._cache:
            if self.mode == MONITOR_MODE_USER and self.ActiveProcess.WoW64Process:
                self._cache['PointerSize'] = 4
            else:
                self._cache['PointerSize'] = 8

        return self._cache['PointerSize']

    @property
    def StackPointer(self):
        if self.mode == MONITOR_MODE_USER and self.ActiveProcess.WoW64Process:
            return ((self.helper.dbg.rsp << 32) >> 32)
        else:
            return self.helper.dbg.rsp

    def __init__(self, helper, Process=None, verbose=False):

        self._cache = {}
        Status = False
        self.Installed = False
        super().__init__(helper, Process=Process, mode=MONITOR_MODE_USER, verbose=verbose)

        self.NotifiedLoadImage = []

        if not hasattr(self, '__install__'):
            return

        if self.Dependencies is None:
            Status = self.__install__()

        elif Process is None or self.ActiveProcess.DirectoryTableBase == Process.DirectoryTableBase:

            Status = self.helper.SymReloadUserModule(self.Dependencies)

            if not Status:
                return
            if self.cr3 is None or self.ActiveProcess.DirectoryTableBase == self.cr3:
                Status = self.__install__()

        if Status:
            self.Installed = True

    def ReadParameters(self, Params, Callback):

        ParsedData = self.Parameters()

        for Index in range(len(Params)):

            fp = Params[Index]
            Value = self.GetParameterByIndex(Index)

            Name = fp.Name
            setattr(ParsedData, Name, Value)

            if not fp.IsInput and not fp.IsReturn:
                continue
            if fp.IsReturn:
                Value = self.PsGetReturnValue()

            this = Value
            if Callback:
                Value = Callback(ParsedData, fp, this)

            if not Value:
                '''
                    Is the function parameter is a pointer and the read virtual memory
                    does not return a valid value, because of swapped page, then the Value
                    can still be None
                '''
                if Value:
                    if fp.Type == 'DWORD':
                        Value &= 0xffffffff
                    elif fp.Type == 'WORD':
                        Value &= 0xffff
                    elif fp.Type == 'BYTE':
                        Value &= 0xFF
                    elif fp.Type == 'BOOL':
                        Value &= 0x1
                else:
                    Value = this

            setattr(ParsedData, Name, Value)

        return ParsedData

    def NotifyLoadImage(self, Process, NotifyLoadImage):
        """ This function assume that the virtual machine is on a PsLoadImageNotifyRoutine
            prolog
        """
        class NotifyLoadImageHandler():

            def __init__(self, monitor, Process, NotifyLoadImage):

                self.monitor = monitor
                self.Process = Process
                self.NotifyLoadImage = NotifyLoadImage

            def __call__(self):

                self.monitor.helper.UnsetBreakpoint(
                    self.monitor.helper.dbg.rip, self.Process.DirectoryTableBase, self)
                Status = self.monitor.helper.SymReloadModule(
                    self.NotifyLoadImage.ImageBase, self.NotifyLoadImage.ImageSize)
                if Status:
                    if self.monitor.__notify_load_image__(self.Process, self.NotifyLoadImage):
                        ImageName = os.path.split(
                            self.NotifyLoadImage.FullImageName)[-1]
                        self.monitor.NotifiedLoadImage.append(
                            ImageName.lower())

                return True

        if len(self.NotifiedLoadImage) == len(self.Dependencies):
            self.Installed = True
            return True

        ImageName = os.path.split(NotifyLoadImage.FullImageName)[-1]
        if self.ActiveProcess.WoW64Process and NotifyLoadImage.Properties.Flag.ImageSignatureType == 1:
            return False
        if ImageName.lower() not in self.Dependencies:
            return False
        if ImageName.lower() in self.NotifiedLoadImage:
            return True
        if self.cr3 != self.ActiveProcess.DirectoryTableBase:
            return False

        o = NotifyLoadImageHandler(
            self, Process=Process, NotifyLoadImage=NotifyLoadImage)
        """ if the current kthread has a TrapFrame then we add a breakpoint in userland
            otherwise we set a breakpoint based on the return address on the stack
        """
        BpAddress = Process.Thread.TrapFrame.Rip
        o.BpId = self.helper.SetBreakpoint(
            BpAddress, o, Process.DirectoryTableBase, description='Monitor.NotifyLoadImage')

        return True

    def SetBreakpoint(self, target, handler):

        if isinstance(target, str):
            if self.ActiveProcess.WoW64Process:
                if target.startswith('ntdll'):
                    target = 'w%s' % target
                if target.startswith('kernel32'):
                    target = 'w%s' % target
            address = self.LookupByName(target)
        else:
            address = target

        if self.helper.ReadVirtualMemory(address, 1) is None:
            self.logger.warning(
                'SetBreakpointError: cannot paged out address %x for %s', address, target)
            raise Exception('ReadVirtualMemoryError')

        return self.helper.SetBreakpoint(address, handler, self.cr3, description=target)

    def SymLookupByAddress(self, Address):

        ActiveProcess = self.helper.PsGetCurrentProcess(loadLdr=True)

        Symbol = self.helper.symbol.LookupByAddr(Address)
        if Symbol is not None:
            return Symbol

        ModuleBaseAddress = None

        if ActiveProcess.WoW64Process:
            Modules = ActiveProcess.LdrData32.Modules
        else:
            Modules = ActiveProcess.LdrData.Modules

        for Module in Modules:
            if Module.DllBase < Address < (Module.DllBase + Module.SizeOfImage):
                ModuleBaseAddress = Module.DllBase
                break

        if ModuleBaseAddress is None:
            return None, None

        self.helper.SymReloadModule(ModuleBaseAddress)
        return self.helper.symbol.LookupByAddr(Address)

class UserlandGenericMonitor(UserlandMonitor):

    def SetBreakpoint(self, target):
        return UserlandMonitor.SetBreakpoint(self, target, self.__generic_handler__)

    def __notify_load_image__(self, Process, LoadImage):
        return self.__install__(NotifyLoadImage=LoadImage)

    def __get_function_name__(self):

        FunctionName = self.LookupByAddr(self.helper.dbg.rip)
        if FunctionName.find('!') != -1:
            Module, FunctionName = FunctionName.split('!')

        if hasattr(self, '__get_canonical_function_name__'):
            FunctionName = self.__get_canonical_function_name__(FunctionName)

        if FunctionName.endswith('A'):
            self.Ansi = True
        elif FunctionName.endswith('W'):
            self.Ansi = False
        else:
            self.Ansi = None

        if FunctionName.endswith('A') or FunctionName.endswith('W'):
            return FunctionName[:-1]
        else:
            return FunctionName

    def __pre_process_parameters__(self, Parameters, Proto, Value):

        if Proto.Type == 'LPCTSTR':
            return self.helper.ReadCString(Value, 260, self.Ansi)
        elif Proto.Type == 'HANDLE' and not Proto.IsPointer:
            if Value == 18446744073709551615:  # -1 for current process
                Value = 'CurrentProcess'
            elif Value == 18446744073709551614:  # -2 for current thread
                Value = 'CurrentThread'
            elif Value == 18446744073709551610:
                Value = 'CurrentToken__'
            else:
                Parameters.Object = self.ActiveProcess.ObReferenceObjectByHandle(
                    Value)

        return Value

    @UserlandMonitor._decorator
    def __generic_handler__(self):
        '''
            @brief Monitor callback for each OpenService event
        '''
        self.FunctionName = self.__get_function_name__()

        Prototype = self.helper.symbol.SymGetApiPrototype(self.FunctionName)
        Parameters = self.ReadParameters(
            Prototype, self.__pre_process_parameters__)

        if hasattr(self, '__post_process_parameters__'):
            self.__post_process_parameters__(Parameters)

        self.LastOperation.Save(Action=self.FunctionName,
                                Process=self.ActiveProcess, Detail=Parameters)

        return True
