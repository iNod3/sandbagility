
from abc import ABC, abstractmethod


class OsHelper(ABC):

    @abstractmethod
    def PsGetCurrentProcess(self, details=False):
        '''
            Function read size bytes from address virtual memory
        '''
        pass

    @abstractmethod
    def PsGetCurrentThread(self):
        pass

    @abstractmethod
    def PsLookupProcessByProcessId(self, ProcessId):
        '''
            Function write buffer from address virtual memory
        '''
        pass

    @abstractmethod
    def PsLookupProcessByProcessName(self, Name):
        '''
            Function write buffer from address virtual memory
        '''
        pass

    @abstractmethod
    def PsEnumProcesses(self, *args, **kwargs):
        '''
            Set breakpoint at address
            return breakpoint ID
         '''
        pass

    @abstractmethod
    def KeGetKernelBaseAddress(self):
        pass

    @abstractmethod
    def KeGetGsVirtualAddress(self):
        pass

    @abstractmethod
    def MoGetImageSize(self, BaseAddress):
        pass

    @abstractmethod
    def MoDumpImage(self, BaseAddress, ImageSize=None):
        pass

    @abstractmethod
    def MoGetEntryPoint(self, Image):
        pass

    @abstractmethod
    def MoIsAddressMapped(self, ModuleImage, Rva):
        pass
