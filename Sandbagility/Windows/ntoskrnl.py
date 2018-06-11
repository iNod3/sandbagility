
import os
import ctypes
import logging
import datetime

import Sandbagility.msr as msr
from Sandbagility.OsHelper import OsHelper


class dummy():
    def __repr__(self):
        d = self.__dict__.copy()
        if 'helper' in d: del d['helper']
        if 'logger' in d: del d['logger']
        return str(d)


class _LIST_ENTRY32(ctypes.Structure):

    _fields_ = [
        ('Flink', ctypes.c_uint32),
        ('Blink', ctypes.c_uint32),
    ]


class _PEB_LDR_DATA32(ctypes.Structure):

    '''
       +0x000 Length           : Uint4B
       +0x004 Initialized      : UChar
       +0x008 SsHandle         : Ptr64 Void
       +0x010 InLoadOrderModuleList : _LIST_ENTRY
       +0x020 InMemoryOrderModuleList : _LIST_ENTRY
       +0x030 InInitializationOrderModuleList : _LIST_ENTRY
       +0x040 EntryInProgress  : Ptr64 Void
       +0x048 ShutdownInProgress : UChar
       +0x050 ShutdownThreadId : Ptr64 Void
    '''
    _fields_ = [

        ('Length', ctypes.c_uint32),
        ('Initialized', ctypes.c_int8),
        ('SsHandle', ctypes.c_uint32),
        ('InLoadOrderModuleList', _LIST_ENTRY32),
        ('InMemoryOrderModuleList', _LIST_ENTRY32),
        ('InInitializationOrderModuleList', _LIST_ENTRY32),
        ('EntryInProgress', ctypes.c_uint32),
        ('ShutdownInProgress', ctypes.c_int8),
        ('ShutdownThreadId', ctypes.c_uint32),

    ]


class _UNICODE_STRING32(ctypes.Structure):
    _fields_ = [
        ('Length', ctypes.c_uint16),
        ('MaximumLength', ctypes.c_uint16),
        ('Buffer', ctypes.c_uint32),
    ]


class _LDR_DATA_TABLE_ENTRY32(ctypes.Structure):
    _fields_ = [
        ('InLoadOrderLinks', _LIST_ENTRY32),
        ('InMemoryOrderLinks', _LIST_ENTRY32),
        ('InInitializationOrderLinks', _LIST_ENTRY32),
        ('DllBase', ctypes.c_uint32),
        ('EntryPoint', ctypes.c_uint32),
        ('SizeOfImage', ctypes.c_uint32),
        ('FullDllName', _UNICODE_STRING32),
        ('BaseDllName', _UNICODE_STRING32),
        ('FlagGroup', ctypes.c_uint8 * 4),
        ('ObsoleteLoadCount', ctypes.c_uint16),
        ('TlsIndex', ctypes.c_uint16),
        ('HashLinks', _LIST_ENTRY32),
        ('TimeDateStamp', ctypes.c_uint32),
    ]



class UnicodeString():

    def __init__(self, Length=0, MaximumLength=0, Buffer=0, Raw=b''):
        self.Length = Length
        self.MaximumLength = MaximumLength
        self.Buffer = Buffer
        self.Raw = Raw

        '''
            Force the str representation to ensure that the
            decoded string is right formated
        '''
        try: self.String = str('%s' % Raw.decode('utf16'))
        except: self.String = None

    def __repr__(self):
        return self.String

    def __str__(self):
        if self.String: return self.String
        else: return self.Raw.hex()

    def __eq__(self, other):
        if not isinstance(other, str): return False

        if self.String.upper() == other.upper(): return True
        else: return False

    def __ne__(self, other): return not self.__eq__(other)

    def __contains__(self, other):
        if not isinstance(other, str): return False
        return other.upper() in self.String.upper()


class DateTime():

    def __init__(self, raw):
        self.Raw = raw
        self.Value = self.__convert_to_time__()

    def __convert_to_time__(self):
        us = self.Raw / 10.
        td = datetime.timedelta(microseconds=us)
        off = datetime.datetime(1601, 1, 1)
        return (off + td)

    def __repr__(self): return str(self.Raw)

    def __str__(self): return '%s' % self.Value


class ClientId(dummy):

    def __init__(self, Pid, Tid=None):
        self.Pid = Pid
        self.Tid = Tid

    def __eq__(self, other):
        return str(self) == str(other)

    def __ne__(self, other): return not self.__eq__(other)

    def __str__(self):
        if self.Tid: return '{:>4x}.{:<x}'.format(self.Pid, self.Tid)
        else: return '{:>4x}'.format(self.Pid)


class ObHeaderObject(dummy):

    def __init__(self, helper, Object):

        self.helper = helper
        self.Object = Object

        self.logger = self.helper.os.logger
        self.TypeName = 'Invalid'
        self.ObjectType = -1
        self.PointerCount = -1
        self.HandleCount = -1

        self.ObjectHeader = self.Object - self.helper.symbol.GetStructureMemberOffset('nt!_OBJECT_HEADER', 'Body')

        EncodedTypeIndex = self.helper.ReadStructureMember8(self.ObjectHeader, 'nt!_OBJECT_HEADER', 'TypeIndex')
        if not EncodedTypeIndex: return

        HeaderCookieAddr = helper.SymLookupByName('ObHeaderCookie')

        self.HeaderCookie = helper.ReadVirtualMemory8(HeaderCookieAddr)
        if not self.HeaderCookie: return

        ObjectAddressCookie = ((self.ObjectHeader >> 8) & 0xff)

        self.TypeIndex = EncodedTypeIndex ^ self.HeaderCookie ^ ObjectAddressCookie

        ObTypeIndexTableAddr = helper.SymLookupByName('ObTypeIndexTable')

        self.ObjectType = self.helper.ReadVirtualMemory64(ObTypeIndexTableAddr + self.TypeIndex * 8)
        if self.ObjectType is None: return

        ObjectTypeNameAddress = self.ObjectType + self.helper.symbol.GetStructureMemberOffset('nt!_OBJECT_TYPE', 'Name')

        self.TypeName = self.helper.ReadUnicodeString(ObjectTypeNameAddress)

        self.PointerCount = self.helper.ReadStructureMember64(self.ObjectHeader, 'nt!_OBJECT_HEADER', 'PointerCount')
        self.HandleCount = self.helper.ReadStructureMember64(self.ObjectHeader, 'nt!_OBJECT_HEADER', 'HandleCount')

    def __str__(self):

        return 'Object: {:x}  Type: ({:x}) {:}\n\
            ObjectHeader: {:x} (new version)\n\
            HandleCount: {:d}  PointerCount: {:d}\n' \
                .format(self.Object, self.ObjectType, self.TypeName,
                        self.ObjectHeader, self.HandleCount, self.PointerCount)


class Ldr(dummy):

    class LdrDataModule():
        def __init__(self): pass

        def __str__(self):
            return '{:>16x}-{:<16x} {:8x} {}'.format(self.DllBase, (self.DllBase + self.SizeOfImage), self.TimeDateStamp, self.FullDllName)

    def __init__(self, helper, address):

        self.helper = helper
        self.Address = address

        self.logger = helper.os.logger

        PebLdrData = self.helper.ReadStructure(self.Address, 'nt!_PEB_LDR_DATA')
        if PebLdrData is None: return

        self.Length = PebLdrData.Length

        self.InLoadOrderModuleList = PebLdrData.InLoadOrderModuleList
        self.InLoadOrderModuleList = self.helper.ReadStructure(self.InLoadOrderModuleList, 'nt!_LIST_ENTRY')
        self.InMemoryOrderModuleList = PebLdrData.InMemoryOrderModuleList
        self.InInitializationOrderModuleList = PebLdrData.InInitializationOrderModuleList

        self.__parse_loaded_module_list__()

    def __parse_loaded_module_list__(self):

        self.Modules = []

        ListEntry = self.helper.ReadStructure(self.InLoadOrderModuleList.Flink, 'nt!_LIST_ENTRY')
        if ListEntry is None: return

        NextLdrDataModuleEntry = ListEntry.Flink

        while (NextLdrDataModuleEntry != self.InLoadOrderModuleList.Flink) and (NextLdrDataModuleEntry is not None):

            if NextLdrDataModuleEntry is None: continue

            LdrDataTableEntry = self.helper.ReadStructure(NextLdrDataModuleEntry, 'nt!_LDR_DATA_TABLE_ENTRY')
            if LdrDataTableEntry is None: break

            if LdrDataTableEntry.DllBase == 0 or LdrDataTableEntry.DllBase is None:
                NextLdrDataModuleEntry = self.helper.ReadStructure(NextLdrDataModuleEntry, 'nt!_LIST_ENTRY')
                if NextLdrDataModuleEntry is None: break

                NextLdrDataModuleEntry = NextLdrDataModuleEntry.Flink
                continue

            LdrDataModuleEntry = self.LdrDataModule()

            setattr(LdrDataModuleEntry, 'DllBase', LdrDataTableEntry.DllBase)
            setattr(LdrDataModuleEntry, 'EntryPoint', LdrDataTableEntry.EntryPoint)
            setattr(LdrDataModuleEntry, 'SizeOfImage', LdrDataTableEntry.SizeOfImage)
            setattr(LdrDataModuleEntry, 'TimeDateStamp', LdrDataTableEntry.TimeDateStamp)
            FullDllName = self.helper.ReadUnicodeString(LdrDataTableEntry.FullDllName)
            setattr(LdrDataModuleEntry, 'FullDllName', FullDllName)

            self.Modules.append(LdrDataModuleEntry)
            NextLdrDataModuleEntry = self.helper.ReadStructure(NextLdrDataModuleEntry, 'nt!_LIST_ENTRY')
            if NextLdrDataModuleEntry is None: break

            NextLdrDataModuleEntry = NextLdrDataModuleEntry.Flink


class Ldr32(dummy):

    class LdrDataModule():
        def __init__(self): pass

        def __str__(self):
            return '{:>16x}-{:<16x} {:8x} {}'.format(self.DllBase, (self.DllBase + self.SizeOfImage), self.TimeDateStamp, self.FullDllName)

    def __init__(self, helper, address):

        self.helper = helper
        self.Address = address

        self.logger = helper.os.logger

        LdrData = self.helper.ReadStructure(self.Address, _PEB_LDR_DATA32)

        if LdrData is None: return

        self.Length = LdrData.Length

        self.InLoadOrderModuleList = LdrData.InLoadOrderModuleList.Flink

        self.InMemoryOrderModuleList = LdrData.InMemoryOrderModuleList.Flink

        self.InInitializationOrderModuleList = LdrData.InInitializationOrderModuleList.Flink

        self.__parse_loaded_module_list__()

    def __parse_loaded_module_list__(self):

        self.Modules = []

        NextLdrDataModuleEntry = self.helper.ReadStructure(self.InLoadOrderModuleList, _LIST_ENTRY32)
        if NextLdrDataModuleEntry is None: return

        NextLdrDataModuleEntry = NextLdrDataModuleEntry.Flink
        while NextLdrDataModuleEntry != self.InLoadOrderModuleList:

            if NextLdrDataModuleEntry is None: continue

            LdrDataTableEntry = self.helper.ReadStructure(NextLdrDataModuleEntry, _LDR_DATA_TABLE_ENTRY32)
            if LdrDataTableEntry is None: break

            if LdrDataTableEntry.DllBase == 0:
                NextLdrDataModuleEntry = self.helper.ReadStructure(NextLdrDataModuleEntry, _LIST_ENTRY32)
                if NextLdrDataModuleEntry is None: break

                NextLdrDataModuleEntry = NextLdrDataModuleEntry.Flink
                continue

            LdrDataModuleEntry = self.LdrDataModule()

            setattr(LdrDataModuleEntry, 'DllBase', LdrDataTableEntry.DllBase)
            setattr(LdrDataModuleEntry, 'EntryPoint', LdrDataTableEntry.EntryPoint)
            setattr(LdrDataModuleEntry, 'SizeOfImage', LdrDataTableEntry.SizeOfImage)
            setattr(LdrDataModuleEntry, 'TimeDateStamp', LdrDataTableEntry.TimeDateStamp)
            setattr(LdrDataModuleEntry, 'FullDllName', self.helper.ReadUnicodeString(LdrDataTableEntry.FullDllName))

            self.Modules.append(LdrDataModuleEntry)
            NextLdrDataModuleEntry = self.helper.ReadStructure(NextLdrDataModuleEntry, _LIST_ENTRY32)
            if NextLdrDataModuleEntry is None: break

            NextLdrDataModuleEntry = NextLdrDataModuleEntry.Flink

class NtObject(dummy):

    OBJECT_TYPE = 'None'

    def __init__(self, helper, Object):

        self.helper = helper

        self.logger = logging.getLogger('{:<30}'.format(self.OBJECT_TYPE))
        if self.OBJECT_TYPE in self.helper.debug: self.logger.setLevel(logging.DEBUG)
        else: self.logger.setLevel(logging.INFO)

        Objectoo = Object

        if isinstance(Object, int):
            Object = ObHeaderObject(self.helper, Object)

        self.ObHeader = Object
        self.Object = Object.Object

        if hasattr(Object, 'TypeName') and Object.TypeName != self.OBJECT_TYPE:
            raise Exception('Invalid object type %s expected %s' % (Object.TypeName, self.OBJECT_TYPE))

    @property
    def TypeName(self): return self.ObHeader.TypeName

# class ProcessObject(NtObject):
class ProcessObject(dummy):

    OBJECT_TYPE = 'Process'

    def __init__(self, helper, eprocess, loadLdr=False):

        # super().__init__(helper, eprocess)

        self.SessionId = -1
        self.LdrData = []
        self.ImageFileName = None
        self.CommandLine = '<empty>'
        self.HandleCount = 0

        self.helper = helper

        self.Object = eprocess
        self.eprocess = self.Object
        self.logger = self.helper.os.logger

        self.__parse_eprocess__(loadLdr)

    def __eq__(self, other):

        if isinstance(other, str):
            return self.ImageFileName.lower() == other.lower()
        elif isinstance(other, int):
            return self.UniqueProcessId == other
        elif isinstance(other, ProcessObject):
            return self.eprocess == other.eprocess
        else:
            self.logger.warning('ProcessObject.__eq__: Invalid other type %s', type(other))
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __set_process_context__(self):
        self.PreviousDirectoryTableBase = self.helper.dbg.cr3
        self.helper.dbg.cr3 = self.DirectoryTableBase

    def __restore_process_context__(self):
        self.helper.dbg.cr3 = self.PreviousDirectoryTableBase

    def __parse_eprocess__(self, loadLdr):

        self.DirectoryTableBase = self.helper.ReadStructureMember64(self.eprocess, 'nt!_KPROCESS', 'DirectoryTableBase')

        self.__set_process_context__()

        EProcess = self.helper.ReadStructure(self.eprocess, 'nt!_EPROCESS')
        self.UniqueProcessId = EProcess.UniqueProcessId

        self.Cid = ClientId(self.UniqueProcessId)

        self.InheritedFromUniqueProcessId = EProcess.InheritedFromUniqueProcessId

        self.WoW64Process = EProcess.WoW64Process

        self.Peb = EProcess.Peb

        if self.Peb:
            self.__parse_peb__(loadLdr=loadLdr)
            self.__parse_rtl_user_process_paramters__()

        if self.WoW64Process:
            self.__parse_peb32__(loadLdr=loadLdr)
            self.__parse_rtl_user_process_paramters__()

        if self.ImageFileName is None:
            self.ImageFileName = bytes(EProcess.ImageFileName)
            self.ImageFileName = self.ImageFileName[0:self.ImageFileName.find(b'\x00')].decode()

        self.CreateTime = DateTime(EProcess.CreateTime)
        self.ExitTime = DateTime(EProcess.ExitTime)

        self.ObjectTable = EProcess.ObjectTable
        self.HandleTableCode = self.helper.ReadStructureMember64(self.ObjectTable, 'nt!_HANDLE_TABLE', 'TableCode')

        pActualEntry = self.helper.GetStructureMemberAddress(self.ObjectTable, 'nt!_HANDLE_TABLE', 'ActualEntry')
        HandleCount = self.helper.ReadVirtualMemory32(pActualEntry + 6 * ctypes.sizeof(ctypes.c_uint))
        if HandleCount is not None: self.HandleCount = HandleCount

        self.__restore_process_context__()

    def __parse_peb__(self, loadLdr=False):

        _Peb = self.helper.ReadStructure(self.Peb, 'nt!_PEB')
        if _Peb is None: return None

        self.Ldr = _Peb.Ldr

        self.ImageBaseAddress = _Peb.ImageBaseAddress

        if loadLdr and self.Ldr:
            self.LdrData = Ldr(self.helper, self.Ldr)
        else: self.LdrData = None

        self.SessionId = _Peb.SessionId
        if not self.SessionId: self.SessionId = -1

        return _Peb

    def __parse_peb32__(self, loadLdr=False):

        Peb32 = self.helper.ReadStructureMember64(self.WoW64Process, 'nt!_EWOW64PROCESS', 'Peb')

        self.ImageBaseAddress = self.helper.ReadStructureMember32(Peb32, 'nt!_PEB32', 'ImageBaseAddress')

        self.Ldr32 = self.helper.ReadStructureMember32(Peb32, 'nt!_PEB32', 'Ldr')

        if loadLdr and self.Ldr32: self.LdrData32 = Ldr32(self.helper, self.Ldr32)
        else: self.LdrData32 = None

    def __parse_rtl_user_process_paramters__(self):

        ProcessParametersPtr = self.helper.ReadStructureMember64(self.Peb, 'nt!_PEB', 'ProcessParameters')
        if ProcessParametersPtr is None: return

        ImagePathNamePtr = self.helper.GetStructureMemberAddress(ProcessParametersPtr, 'nt!_RTL_USER_PROCESS_PARAMETERS', 'ImagePathName')

        self.ImagePathName = self.helper.ReadUnicodeString(ImagePathNamePtr)
        if self.ImagePathName is not None:
            self.ImageFileName = os.path.split(str(self.ImagePathName))[-1]

        CommandLinePtr = self.helper.GetStructureMemberAddress(ProcessParametersPtr, 'nt!_RTL_USER_PROCESS_PARAMETERS', 'CommandLine')

        self.CommandLine = self.helper.ReadUnicodeString(CommandLinePtr)

    def __ObReferenceObjectByHandle__(self, Handle):

        HANDLE_TO_OFFSET = 4
        MAX_HANDLE_PER_TABLE = 0x100  # _HANDLE_TABLE_ENTRY size

        if Handle & 0x80000000:
            ObpKernelHandleTableAddress = self.helper.SymLookupByName('ObpKernelHandleTable')
            ObpKernelHandleTable = self.helper.ReadVirtualMemory64(ObpKernelHandleTableAddress)
            RootHandleTableCode = self.helper.ReadVirtualMemory64(ObpKernelHandleTable + 8)
            Handle = (((Handle << 32) >> 32) & ~0xffffffff80000000)
        else:
            RootHandleTableCode = self.HandleTableCode  # ( HandleTableCode >> 8 ) << 8
        '''
        Check if the primary HandleTableCode has indirect HandleTableCode
        '''
        if RootHandleTableCode & 0xff:
            '''
            Convert the handle to its handle table code index
            '''
            RootHandleTableCodeAligned = ((RootHandleTableCode >> 8) << 8)
            HandleTableCodeIndex = int(Handle / HANDLE_TO_OFFSET / MAX_HANDLE_PER_TABLE)
            HandleTableCode = self.helper.ReadVirtualMemory64(RootHandleTableCodeAligned + HandleTableCodeIndex * 8)

        else:
            HandleTableCode = RootHandleTableCode

        if HandleTableCode is None: return None
        Entry = HandleTableCode + ((Handle * HANDLE_TO_OFFSET) & 0xff0)

        ObjectHeader = self.helper.ReadVirtualMemory64(Entry)
        if not ObjectHeader: return None

        ObjectHeader = (ObjectHeader >> 16) | (0xffff << 48)
        ObjectHeader = ((ObjectHeader >> 4) << 4)

        Object = ObjectHeader + self.helper.symbol.GetStructureMemberOffset('nt!_OBJECT_HEADER', 'Body')

        offset = self.helper.symbol.GetStructureMemberOffset('nt!_HANDLE_TABLE_ENTRY', 'GrantedAccessBits')
        GrantedAccess = self.helper.ReadVirtualMemory64(Entry + offset)

        return Object

    def ObReferenceObjectByHandle(self, Handle):

        ObReference = self.__ObReferenceObjectByHandle__(Handle)
        if not ObReference: return None

        NtObject = ObHeaderObject(self.helper, ObReference)
        if NtObject.TypeName == 'File': return FileObject(self.helper, NtObject)
        elif NtObject.TypeName == 'Key': return KeyObject(self.helper, NtObject)
        elif NtObject.TypeName == 'Process': return ProcessObject(self.helper, NtObject.Object)
        elif NtObject.TypeName == 'Thread': return ThreadObject(self.helper, NtObject.Object)
        elif NtObject.TypeName == 'Invalid': return None
        else: return NtObject

    def __str__(self):
        str_ = '\n'
        str_ += 'PROCESS %.16x\n' % self.eprocess
        str_ += 'SessionId: {:>8x}  Cid: {}    Peb: {:16x}  ParentCid: {:4x}\n'.format(
                self.SessionId, self.Cid, self.Peb, self.InheritedFromUniqueProcessId)
        str_ += 'DirBase: %8x  ObjectTable: %.16x  HandleCount: %d\n' % (self.DirectoryTableBase, self.ObjectTable, self.HandleCount)
        str_ += 'Image: %s\n' % self.ImageFileName

        if self.LdrData and hasattr(self.LdrData, 'Modules'):
            for module in self.LdrData.Modules:
                str_ += '%s\n' % module

        if hasattr(self, 'LdrData32') and self.LdrData32:
            if hasattr(self.LdrData32, 'Modules'):
                for module in self.LdrData32.Modules:
                    str_ += '%s\n' % module

        return str_


# class ThreadObject(NtObject):
class ThreadObject(dummy):

    OBJECT_TYPE = 'Thread'

    def __init__(self, helper, ethread):

        self.helper = helper

        self.ethread = ethread

        self.logger = helper.os.logger

        self.__parse_ethread__()
        self.__parse_trap_frame__()

    def __repr__(self):
        d = self.__dict__.copy()
        if 'helper' in d: del d['helper']
        if 'logger' in d: del d['logger']
        if 'TrapFrame' in d: del d['TrapFrame']
        return str(d)

    def __parse_ethread__(self):

        self.Process = self.helper.ReadStructureMember64(self.ethread, 'nt!_KTHREAD', 'Process')

        CidPtr = self.helper.GetStructureMemberAddress(self.ethread, 'nt!_ETHREAD', 'Cid')

        Pid = self.helper.ReadStructureMember64(CidPtr, 'nt!_CLIENT_ID', 'UniqueProcess')
        Tid = self.helper.ReadStructureMember64(CidPtr, 'nt!_CLIENT_ID', 'UniqueThread')

        self.Cid = ClientId(Pid, Tid)

        self.Teb = self.helper.ReadStructureMember64(self.ethread, 'nt!_KTHREAD', 'Teb')

        if self.Teb: self.__parse_nt_tib__()

    def __parse_nt_tib__(self):

        self.StackBase = self.helper.ReadStructureMember64(self.Teb, 'nt!_NT_TIB', 'StackBase')

        self.StackLimit = self.helper.ReadStructureMember64(self.Teb, 'nt!_NT_TIB', 'StackLimit')

    def __parse_trap_frame__(self):

        TrapFramePtr = self.helper.ReadStructureMember64(self.ethread, 'nt!_KTHREAD', 'TrapFrame')

        if TrapFramePtr == 0: return

        self.TrapFrame = self.helper.ReadStructure(TrapFramePtr, 'nt!_KTRAP_FRAME')


class FileObject(NtObject):

    OBJECT_TYPE = 'File'

    def __init__(self, helper, Object):

        NtObject.__init__(self, helper, Object)

        self.logger = self.helper.os.logger

        FileNameAddress = self.Object + self.helper.symbol.GetStructureMemberOffset('nt!_FILE_OBJECT', 'FileName')

        self.Name = self.helper.ReadUnicodeString(FileNameAddress)

        pDeviceObject = self.helper.ReadStructureMember64(self.Object, 'nt!_FILE_OBJECT', 'DeviceObject')

        self.DeviceObject = self.helper.ReadStructure(pDeviceObject, 'nt!_DEVICE_OBJECT')

        self.DriverObject = self.helper.ReadStructure(self.DeviceObject.DriverObject, 'nt!_DRIVER_OBJECT')

        self.DriverName = self.helper.ReadUnicodeString(bytes(self.DriverObject.DriverName))

    def __str__(self):
        return '%s' % (self.Name)

    def __repr__(self):
        return str(self.Name)


class KeyObject(NtObject):

    OBJECT_TYPE = 'Key'

    def __init__(self, helper, Object):

        NtObject.__init__(self, helper, Object)

        self.__parse_key_body__()

    def __read_name_control_block__(self, KeyControlBlockPtr):

        NameBlockPtr = self.helper.ReadStructureMember64(KeyControlBlockPtr, 'nt!_CM_KEY_CONTROL_BLOCK', 'NameBlock')

        NameLength = self.helper.ReadStructureMember8(NameBlockPtr, 'nt!_CM_NAME_CONTROL_BLOCK', 'NameLength')
        if NameLength is None: return None

        NameOffset = self.helper.symbol.GetStructureMemberOffset('nt!_CM_NAME_CONTROL_BLOCK', 'Name')
        Name = self.helper.ReadVirtualMemory(NameBlockPtr + NameOffset, NameLength)

        return Name.decode()

    def __parse_key_name__(self):

        KeyControlBlockPtr = self.helper.ReadStructureMember64(self.Object, 'nt!_CM_KEY_BODY', 'KeyControlBlock')
        if not KeyControlBlockPtr: return

        KeyName = []
        ParentKcb = KeyControlBlockPtr

        while ParentKcb:

            ParentName = self.__read_name_control_block__(ParentKcb)
            if ParentName not in KeyName: KeyName.append(ParentName)
            ParentKcb = self.helper.ReadStructureMember64(ParentKcb, 'nt!_CM_KEY_CONTROL_BLOCK', 'ParentKcb')

        if KeyName == []:
            self.logger.warning('KeyObject:Name: <Empty>')
        else:
            KeyName.reverse()
            self.Name = '\\'.join(map(str, KeyName))

    def __parse_key_body__(self):

        self.__parse_key_name__()
        self.ProcessId = self.helper.ReadStructureMember64(self.Object, 'nt!_CM_KEY_BODY', 'ProcessID')


class Windows(OsHelper):

    PAGEMASK = 0xc
    PAGESIZE = 0x1000

    _NAME = 'Windows'

    def __init__(self, helper, debug=False):
        '''
            @brief Initialize the OsHelper class for windows
        '''
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')

        self.helper = helper
        self.logger = logging.getLogger('{:<20}'.format(self._NAME))

        if self._NAME in self.helper.debug: self.logger.setLevel(logging.DEBUG)
        else: self.logger.setLevel(logging.INFO)

    def __get_gs_base_address__(self):
        '''
            @brief This function return the segment gs virtual base address
            depending on the MSR_GS_BASE or the MSR_KERNEL_GS_BASE. The test
            is done by an heuristic on the address value
        '''
        GsBase = self.helper.dbg.ReadMsr(msr.MSR_GS_BASE)
        if not (GsBase & 0xfff0000000000000):
            GsBase = self.helper.dbg.ReadMsr(msr.MSR_KERNEL_GS_BASE)

        return GsBase

    def ReadUnicodeString(self, Input):
        '''
            @brief This function read the UnicodeString structure as
            defined by the Windows and return a UnicodeString Object
        '''
        if isinstance(Input, int):
            VirtualAddress = Input

            if None is VirtualAddress: return None

            Structure = self.helper.ReadStructure(VirtualAddress, 'nt!_UNICODE_STRING')
            if not Structure: return None
            if None is Structure.Length: return None

            if None is Structure.MaximumLength: return None

            BufferPtr = Structure.Buffer

        elif isinstance(Input, _UNICODE_STRING32):
            Structure = Input

        elif isinstance(Input, bytes):
            Structure = self.helper.ReadStructure(Input, 'nt!_UNICODE_STRING')
        else:
            try: Structure = self.helper.ReadStructure(bytes(Input), 'nt!_UNICODE_STRING')
            except:
                raise Exception('ReadUnicodeStringError: %s' % type(Input))

        Length = Structure.Length
        MaximumLength = Structure.MaximumLength
        BufferPtr = Structure.Buffer

        if None is BufferPtr: return None

        if 0 == BufferPtr or 0 == Length:
            return UnicodeString(Length, MaximumLength, BufferPtr, b'')
        else:
            Raw = self.helper.dbg.ReadVirtualMemory(BufferPtr, Length)
            if not Raw: return None

            return UnicodeString(Length, MaximumLength, BufferPtr, Raw)

    def PsGetCurrentThread(self):
        '''
            @brief Return the current tread context
        '''
        GsBase = self.__get_gs_base_address__()

        CurrentPrcb = self.helper.ReadStructureMember64(GsBase, 'nt!_KPCR', 'CurrentPrcb')
        CurrentThread = self.helper.ReadStructureMember64(CurrentPrcb, 'nt!_KPRCB', 'CurrentThread')

        return ThreadObject(self.helper, CurrentThread)

    def PsGetCurrentProcess(self, loadLdr=False):
        '''
            @brief Return the current process context
            The Current process is slightly deferent from a native ProcessObject
            because it contains some information base on the current thread
        '''
        CurrentThread = self.PsGetCurrentThread()  # ThreadObject(self.helper, EThread)
        ActiveProcess = ProcessObject(self.helper, CurrentThread.Process, loadLdr=loadLdr)
        ActiveProcess.Cid.Tid = CurrentThread.Cid.Tid

        ActiveProcess.Thread = CurrentThread

        return ActiveProcess

    def PsEnumProcesses(self, loadLdr=False):
        '''
            @brief Enumerate all process linked by the ActiveProcessLink
        '''
        ActiveProcessLinkOffset = self.helper.symbol.GetStructureMemberOffset('nt!_EPROCESS', 'ActiveProcessLinks')

        PsActiveProcessHead = self.helper.SymLookupByName('PsActiveProcessHead')
        ActiveProcessLink = self.helper.ReadVirtualMemory64(PsActiveProcessHead)

        while PsActiveProcessHead != ActiveProcessLink:
            yield ProcessObject(self.helper, ActiveProcessLink - ActiveProcessLinkOffset, loadLdr=loadLdr)
            ActiveProcessLink = self.helper.ReadVirtualMemory64(ActiveProcessLink)

    def PsLookupProcessByProcessId(self, ProcessId, *args, **kwargs):
        '''
            @brief Lookup a ProcessObject by its ProcessId
        '''
        Process = self.PsGetCurrentProcess(*args, **kwargs)
        if Process.UniqueProcessId != ProcessId:

            for Process in self.PsEnumProcesses(*args, **kwargs):
                if Process.UniqueProcessId != ProcessId: continue
                break

        return Process

    def PsLookupProcessByProcessName(self, ProcessName, *args, **kwargs):

        for Process in self.PsEnumProcesses(*args, **kwargs):
            if isinstance(ProcessName, str):
                if Process == ProcessName: yield Process
            elif isinstance(ProcessName, list):
                for SingleProcessName in ProcessName:
                    if Process == SingleProcessName: yield Process

    def PsEnumLoadedModule(self):
        '''
            @brief Enumerate all kernel module loaded linked by the PsLoadedModuleList
        '''
        class LoadedModule():
            def __init__(self): pass

            def __str__(self):
                return '{:>16x}-{:<16x} {:8x} {}'.format(self.ImageBase, (self.ImageBase + self.ImageSize), (self.EntryPoint), self.DriverPath)

        class _LOAD_MODULE_DATABASE_ENTRY(ctypes.Structure):
            _fields_ = [

                ('Next', ctypes.c_uint64),
                ('Previous', ctypes.c_uint64),
                ('Reserved0', ctypes.c_uint64),
                ('Reserved1', ctypes.c_uint64),
                ('Reserved2', ctypes.c_uint64),
                ('Reserved3', ctypes.c_uint64),
                ('ImageBase', ctypes.c_uint64),
                ('EntryPoint', ctypes.c_uint64),
                ('ImageSize', ctypes.c_uint64),

            ]

        class _UNICODE_STRING(ctypes.Structure):
            _fields_ = [

                ('Length', ctypes.c_uint16),
                ('MaximumLength', ctypes.c_uint16),
                ('Buffer', ctypes.c_uint64),

            ]

        '''
            Retrieve the address of the PsLoadedModuleList
        '''
        PsLoadedModuleList = self.helper.SymLookupByName('PsLoadedModuleList')
        '''
            For each module in the PsLoadedModuleList parse the _LOAD_MODULE_DATABASE_ENTRY structure
            and create a new LoadedModule object with all information
        '''
        LoadedModuleDatabaseEntryAddress = self.helper.ReadVirtualMemory64(PsLoadedModuleList)
        while PsLoadedModuleList != LoadedModuleDatabaseEntryAddress:

            LdModule = LoadedModule()

            Buffer = self.helper.ReadVirtualMemory(LoadedModuleDatabaseEntryAddress, ctypes.sizeof(_LOAD_MODULE_DATABASE_ENTRY))

            LoadedModuleDatabaseEntry = _LOAD_MODULE_DATABASE_ENTRY.from_buffer_copy(Buffer)
            setattr(LdModule, 'ImageBase', LoadedModuleDatabaseEntry.ImageBase)
            setattr(LdModule, 'EntryPoint', LoadedModuleDatabaseEntry.EntryPoint)
            setattr(LdModule, 'ImageSize', LoadedModuleDatabaseEntry.ImageSize)

            DriverPathPtr = LoadedModuleDatabaseEntryAddress + ctypes.sizeof(_LOAD_MODULE_DATABASE_ENTRY)
            DriverPath = self.helper.ReadUnicodeString(DriverPathPtr)
            setattr(LdModule, 'DriverPath', DriverPath)

            DriverNamePtr = DriverPathPtr + ctypes.sizeof(_UNICODE_STRING)
            DriverName = self.helper.ReadUnicodeString(DriverNamePtr)
            setattr(LdModule, 'DriverName', DriverName)

            '''
                Yield all the result for an iteration purpose
            '''
            yield LdModule

            LoadedModuleDatabaseEntryAddress = self.helper.ReadVirtualMemory64(LoadedModuleDatabaseEntryAddress)
    
    def KeGetGsVirtualAddress(self):
        return self.__get_gs_base_address__()

    def KeGetKernelBaseAddress(self):
        '''
            @brief This function perform an heuristic research of the kernel base address
            from the address store in the MSR_LSTAR.
        '''
        Msr = self.helper.dbg.ReadMsr(msr.MSR_LSTAR)
        '''
            Make page alignment of the address stored by the MSR_LSTAR
        '''
        MsrAligned = ((Msr >> self.PAGEMASK) << self.PAGEMASK)
        KernelPageAddr = MsrAligned

        while (True):
            KernelBase = self.helper.dbg.ReadVirtualMemory(KernelPageAddr, self.PAGESIZE)

            if KernelBase is not None and KernelBase.startswith(b'MZ'):
                return KernelPageAddr
            KernelPageAddr -= self.PAGESIZE

    def KeGetKernelInformation(self):

        class _IMAGE_DOS_HEADER(ctypes.Structure):
            _fields_ = [
                ('Padding', ctypes.c_uint8 * 0x3c),
                ('e_lfanew', ctypes.c_uint32),
            ]


        class _IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
            _fields_ = [
                ('Padding_0', ctypes.c_uint8 * 0x10),
                ('AddressOfEntryPoint', ctypes.c_uint32),
                ('Padding_14', ctypes.c_uint8 * 0x24),
                ('SizeOfImage', ctypes.c_uint32),
            ]


        class _IMAGE_NT_HEADERS64(ctypes.Structure):
            _fields_ = [
                ('Signature', ctypes.c_uint32),
                ('FileHeader', ctypes.c_uint8 * 0x14),
                ('OptionalHeader', _IMAGE_OPTIONAL_HEADER64),
            ]

        KernelBaseAddress = self.KeGetKernelBaseAddress()
        self.logger.debug('Kernel base address found at %#x' % KernelBaseAddress)

        KernelImageHeader = self.MoDumpImage(KernelBaseAddress, ImageSize=self.PAGESIZE)

        ImageDosHeader = self.helper.ReadStructure(KernelImageHeader, _IMAGE_DOS_HEADER)
        ImageNtHeaders = self.helper.ReadStructure(KernelImageHeader[ImageDosHeader.e_lfanew:], _IMAGE_NT_HEADERS64)

        KernelImageSize = ImageNtHeaders.OptionalHeader.SizeOfImage
        self.logger.debug('Kernel module dumped with %#x bytes' % KernelImageSize)

        return (KernelBaseAddress, KernelImageSize)

    def MoGetImageDirectoryEntry(self, ImageNtHeaders, Entry):
        
        _IMAGE_DATA_DIRECTORY = self.helper.symbol.PdbToCTypes('nt!_IMAGE_DATA_DIRECTORY')

        ImageOptionalHeader = self.MoGetImageOptionalHeader(ImageNtHeaders)

        StartOffset = Entry*ctypes.sizeof(_IMAGE_DATA_DIRECTORY)
        EndOffset = StartOffset + ctypes.sizeof(_IMAGE_DATA_DIRECTORY)
        ImageDataDirectory = ImageOptionalHeader.DataDirectory[StartOffset:EndOffset]

        return self.helper.ReadStructure(ImageDataDirectory, 'nt!_IMAGE_DATA_DIRECTORY')

    def MoGetImageDebugDirectory(self, ImageBaseAddress):

        ImageNtHeaders = self.MoGetImageNtHeaders(ImageBaseAddress)

        ImageDirectoryEntryDebug = self.MoGetImageDirectoryEntry(ImageNtHeaders, 6)
        ImageDebugDirectory = self.helper.ReadStructure(ImageBaseAddress+ImageDirectoryEntryDebug.VirtualAddress, 'nt!_IMAGE_DEBUG_DIRECTORY')
        
        return ImageDebugDirectory

    def MoGetImageOptionalHeader(self, ImageNtHeaders):

        ImageOptionalHeader = self.helper.ReadStructure(ImageNtHeaders.OptionalHeader, 'nt!_IMAGE_OPTIONAL_HEADER64')
    
        if ImageOptionalHeader.Magic == 0x10B:
            ImageOptionalHeader = self.helper.ReadStructure(ImageNtHeaders.OptionalHeader, 'nt!_IMAGE_OPTIONAL_HEADER32')
            
        return ImageOptionalHeader

    def MoGetImageNtHeaders(self, ImageBaseAddress):

        ImageDosHeader = self.helper.ReadStructure(ImageBaseAddress, 'nt!_IMAGE_DOS_HEADER')
        ImageNtHeaders = self.helper.ReadStructure(ImageBaseAddress + ImageDosHeader.e_lfanew, 'nt!_IMAGE_NT_HEADERS64')
        return ImageNtHeaders

    def MoGetRsdsDebugInformation(self, ImageBaseAddress):

        ImageDebugDirectory = self.MoGetImageDebugDirectory(ImageBaseAddress)
        if ImageDebugDirectory is None: return None
            
        RawData = self.helper.ReadVirtualMemory(ImageBaseAddress+ImageDebugDirectory.AddressOfRawData, ImageDebugDirectory.SizeOfData)
        Rsds = self.MoParseRsdsRawData(RawData)
        if Rsds is None: return None

        if Rsds.CvSignature != b'RSDS': return None
            
        return Rsds

    def MoParseRsdsRawData(self, RawData):

        class _RSDS_INFO(ctypes.Structure):

            _fields_ = [
                ('CvSignature', ctypes.c_char * 4),
                ('Data1', ctypes.c_uint32),
                ('Data2', ctypes.c_uint16),
                ('Data3', ctypes.c_uint16),
                ('Data4', (ctypes.c_byte * 8)),
                ('Age', ctypes.c_uint32),
            ]

        Rsds = self.helper.ReadStructure(RawData, _RSDS_INFO)
        if Rsds is None: return None

        Rsds.Name = RawData[ctypes.sizeof(_RSDS_INFO):ctypes.sizeof(_RSDS_INFO) + RawData[ctypes.sizeof(_RSDS_INFO):].find(b'\x00')]

        return Rsds        

    def MoGetEntryPoint(self, ImageBaseAddress):
        '''
            @brief This function return the entry point for the given module image
        '''
        ImageNtHeaders = self.MoGetImageNtHeaders(ImageBaseAddress)
        OptionalHeader = self.MoGetImageOptionalHeader(ImageNtHeaders)

        return OptionalHeader.AddressOfEntryPoint

    def MoGetImageSize(self, ImageBaseAddress):
        '''
            @brief This function return the image size of the given module based on its header
        '''
        ImageNtHeaders = self.MoGetImageNtHeaders(ImageBaseAddress)
        OptionalHeader = self.MoGetImageOptionalHeader(ImageNtHeaders)

        return OptionalHeader.SizeOfImage

    def MoIsAddressMapped(self, pImageNtHeaders, Rva):
        '''
            @brief This function check if the virtual address is mapped by the header
            information
        '''
        Status = self.helper.symbol.dbghelp.ImageRvaToSection(pImageNtHeaders, None, ctypes.c_ulong(Rva))
        if Status is None: return False
        else: return True

    def MoDumpImage(self, BaseAddress, ImageSize=None, Callback=None):
        '''
            @brief This function dump a memory range, if the memory range is a module
            then, the function try to retrieve its ImageSize, otherwise the ImageSize parameter
            should not be None.

            @warning If the InjectInterrupt is True, then the function try to inject
            page fault interruption, this should be done only if the current process context
            is within the userland address space. Otherwise, a blue screen will occur.
        '''
        ModuleImage = b''

        '''
            if no ImageSize is given, then we assume that it is a module image. So we parse
            the module header to retrieve the ImageSize
        '''
        if ImageSize is None: ImageSize = self.MoGetImageSize(BaseAddress)

        '''
            For each page we read the virtual memory from the process. If the returned data is none
            we consider that the page is swapped. If no action is required the swapped page is filled
            we zero. If the InjectInterrupt is requested, first of all we check if the page
            is a valid address inside the module by resolving the rva to its related section
        '''
        Page = BaseAddress
        while Page < BaseAddress + ImageSize:

            ModulePage = self.helper.dbg.ReadVirtualMemory(Page, self.PAGESIZE)
            if ModulePage is None: ModulePage = b'\x00' * self.PAGESIZE

            ModuleImage += ModulePage
            if Callback:
                if Callback(ModulePage):
                    return ModuleImage
            Page += self.PAGESIZE

        return ModuleImage
