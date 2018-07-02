import os
import ctypes
import logging
import re
import requests


class dummy():
    def __repr__(self):
        d = self.__dict__.copy()
        if 'helper' in d: del d['helper']
        if 'logger' in d: del d['logger']
        return str(d)


class FunctionParameter(dummy):

    def __init__(self, Name=None, Type=None, Direction=None, Callback=None, Context=None, Function=None):
        self.Name = Name
        self.Type = Type
        self.Direction = Direction
        self.Callback = Callback
        self.Context = Context
        self.Function = Function

    def __is_pointer__(self, type):
        if not type or len(type) < 2: return False
        if type[0] == 'P' and type[1] != 'P': return True
        if type[0] == 'P' and type[1] == 'P': return True
        return False

    @property
    def Type(self): return self._Type

    @Type.setter
    def Type(self, value):
        self._raw_type = value
        self.IsPointer = self.__is_pointer__(value)
        if self.IsPointer:
            self._Type = value[1:]
        else: self._Type = value

    @property
    def IsInput(self):
        if 'in' in self.Direction.lower(): return True
        return False

    @property
    def IsOutput(self):
        if 'out' in self.Direction.lower(): return True
        return False

    @property
    def IsOptional(self):
        if 'opt' in self.Direction.lower(): return True
        return False

    @property
    def IsReturn(self):
        if 'ret' in self.Direction.lower(): return True
        return False


class Symbol():

    class RSDS_INFO(ctypes.Structure):

        _fields_ = [
            ('CvSignature', ctypes.c_uint32),
            ('Data1', ctypes.c_uint32),
            ('Data2', ctypes.c_uint16),
            ('Data3', ctypes.c_uint16),
            ('Data4', (ctypes.c_byte * 8)),
            ('Age', ctypes.c_uint32),
        ]

    class SYM_INFO(ctypes.Structure):

        MAX_SYM_NAME = 2000

        _fields_ = [("SizeOfStruct", ctypes.c_uint32),
                    ("TypeIndex", ctypes.c_uint32),
                    ("Reserved", ctypes.c_uint64 * 2),
                    ("Index", ctypes.c_uint32),
                    ("Size", ctypes.c_uint32),
                    ("ModBase", ctypes.c_uint64),
                    ("Flags", ctypes.c_uint32),
                    ("Value", ctypes.c_uint64),
                    ("Address", ctypes.c_uint64),
                    ("Register", ctypes.c_uint32),
                    ("Scope", ctypes.c_uint32),
                    ("Tag", ctypes.c_uint32),
                    ("NameLen", ctypes.c_uint32),
                    ("MaxNameLen", ctypes.c_uint32),
                    ("Name", ctypes.c_char * (MAX_SYM_NAME + 1))]

    class IMAGEHLP_SYMBOL_TYPE_INFO ():

        TI_GET_SYMTAG = 0
        TI_GET_SYMNAME = 1
        TI_GET_LENGTH = 2
        TI_GET_TYPE = 3
        TI_GET_TYPEID = 4
        TI_GET_BASETYPE = 5
        TI_GET_ARRAYINDEXTYPEID = 6
        TI_FINDCHILDREN = 7
        TI_GET_DATAKIND = 8
        TI_GET_ADDRESSOFFSET = 9
        TI_GET_OFFSET = 10
        TI_GET_VALUE = 11
        TI_GET_COUNT = 12
        TI_GET_CHILDRENCOUNT = 13
        TI_GET_BITPOSITION = 14
        TI_GET_VIRTUALBASECLASS = 15
        TI_GET_VIRTUALTABLESHAPEID = 16
        TI_GET_VIRTUALBASEPOINTEROFFSET = 17
        TI_GET_CLASSPARENTID = 18
        TI_GET_NESTED = 19
        TI_GET_SYMINDEX = 20
        TI_GET_LEXICALPARENT = 21
        TI_GET_ADDRESS = 22
        TI_GET_THISADJUST = 23
        TI_GET_UDTKIND = 24
        TI_IS_EQUIV_TO = 25
        TI_GET_CALLING_CONVENTION = 26
        TI_IS_CLOSE_EQUIV_TO = 27
        TI_GTIEX_REQS_VALID = 28
        TI_GET_VIRTUALBASEOFFSET = 29
        TI_GET_VIRTUALBASEDISPINDEX = 30
        TI_GET_IS_REFERENCE = 31
        TI_GET_INDIRECTVIRTUALBASECLASS = 32
        TI_GET_VIRTUALBASETABLETYPE = 33

    SymTagEnum = [
        'SymTagNull',
        'SymTagExe',
        'SymTagCompiland',
        'SymTagCompilandDetails',
        'SymTagCompilandEnv',
        'SymTagFunction',
        'SymTagBlock',
        'SymTagData',
        'SymTagAnnotation',
        'SymTagLabel',
        'SymTagPublicSymbol',
        'SymTagUDT',
        'SymTagEnum',
        'SymTagFunctionType',
        'SymTagPointerType',
        'SymTagArrayType',
        'SymTagBaseType',
        'SymTagTypedef',
        'SymTagBaseClass',
        'SymTagFriend',
        'SymTagFunctionArgType',
        'SymTagFuncDebugStart',
        'SymTagFuncDebugEnd',
        'SymTagUsingNamespace',
        'SymTagVTableShape',
        'SymTagVTable',
        'SymTagCustom',
        'SymTagThunk',
        'SymTagCustomType',
        'SymTagManagedType',
        'SymTagDimension',
        'SymTagCallSite',
        'SymTagMax',
    ]

    _NAME = '{:<20}'.format('Symbol')

    def __init__(self, debug=[]):

        self.logger = logging.getLogger(self._NAME)

        if 'Symbol' in debug: self.logger.setLevel(logging.DEBUG)

        try: self.dbghelp = ctypes.windll.LoadLibrary('dbghelp.dll')
        except: raise Exception("LoadLibraryError: {} not found".format('dbghelp.dll'))

        self.dbghelp.SymLoadModuleEx.restype = ctypes.c_void_p
        self.dbghelp.SymFromName.restype = ctypes.c_bool
        self.dbghelp.SymFromAddr.restype = ctypes.c_bool
        self.dbghelp.SymEnumSymbols.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_void_p, ctypes.py_object]

        self.dbghelp.ImageNtHeader.restype = ctypes.c_void_p
        self.dbghelp.ImageNtHeader.argtypes = [ctypes.c_void_p]

        self.dbghelp.ImageRvaToSection.restype = ctypes.c_void_p
        self.dbghelp.ImageRvaToSection.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]

        self.logger.debug('dbghelp: %s', self.dbghelp)
        self.hProcess = ctypes.windll.kernel32.GetCurrentProcess()
        self.logger.debug('hProcess: %x', self.hProcess)

        self.loaded_modules = {}
        self._cache = {}
        self._cache_ctypes = {}
        self._cache_prototypes = {}

        self.path = os.getenv('_NT_SYMBOL_PATH')
        if self.path is None: self.logger.error('Set _NT_SYMBOL_PATH to your current symbol directory')

        if self.path.find('*') != -1:
            try: self.path = self.path.split('*')[1]
            except: pass
        self.logger.debug('SymbolPath:%s', self.path)

        if not self.dbghelp.SymInitialize(self.hProcess, None, False):
            raise Exception('SymInitialize failed')

        self.__load_include_files__()

    def __load_include_files__(self):

        IncludePath = os.path.join( os.path.split(__file__)[0], 'inc')

        self.NtApiFileContent = open(os.path.join(IncludePath, 'syscall.h'), 'r').read()
        self.Win32FileContent = open(os.path.join(IncludePath, 'win32.h'), 'r').read()

    def SymGetSyscallPrototype(self, syscall, callback=None):

        if syscall in self._cache_prototypes: return self._cache_prototypes[syscall]
        if self.NtApiFileContent.find(syscall) == -1: return None

        Prototype = []

        # TODO: precompile patter at initialization
        rePattern = 'NTSYSCALLAPI\nNTSTATUS\nNTAPI\n%s\(([^;]*)\);' % syscall
        reParameter = '((_\S*_).*) ([A-Z|_]+) (\**([^,]*))'

        '''
            @Brief read input parameters
        '''
        rawPrototype = re.findall(rePattern, self.NtApiFileContent)[0]

        for Parameter in rawPrototype.split('\n'):

            if not Parameter or not Parameter.strip(): continue

            try:
                Matches = re.findall(reParameter, Parameter)[0][1:]
                fp = FunctionParameter(Name=Matches[3], Type=Matches[1], Direction=Matches[0], Function=syscall)

            except: continue

            if callback: callback(fp)
            Prototype.append(fp)

            self.logger.debug('GetSyscallParameter.Prototype: %s', fp.__dict__)

        fp = FunctionParameter(Name='Return', Type='ULONG', Direction='_Ret_', Function=syscall)
        Prototype.append(fp)

        self._cache_prototypes[syscall] = Prototype

        return Prototype

    def SymGetApiPrototype(self, api):

        if api in self._cache_prototypes: return self._cache_prototypes[api]

        PrototypeInfo = []

        rePattern = '([A-Z]+) WINAPI %s\(([^;]*)\);' % api
        reParameter = '((_\S*_).*) (([A-Z|_]+) \**)\s*([^,]*)'

        try: Return, Prototype = re.findall(rePattern, self.Win32FileContent)[0]
        except: raise Exception('SymbolError: Cannot retrieve the prototype for %s' % api)

        '''
            @Brief read input parameters
        '''
        for Parameter in Prototype.split('\n'):
            if not Parameter: continue
            try:

                Matches = re.findall(reParameter, Parameter)[0]

                if '*' in Matches[2] or Matches[2].startswith('LP'): Type = 'P' + Matches[3]
                else: Type = Matches[3]

                fp = FunctionParameter(Name=Matches[4], Direction=Matches[1], Type=Type, Function=api)

            except: continue

            PrototypeInfo.append(fp)

        fp = FunctionParameter(Direction='_Ret_', Name='Return', Type=Return, Function=api)
        PrototypeInfo.append(fp)

        self._cache_prototypes[api] = PrototypeInfo

        return PrototypeInfo
       
    def SymGetModulePdbPath(self, Rsds):

        module = os.path.split(Rsds.Name.decode())[-1]
        uuid = ("{:08x}{:04x}{:04x}{:}{:x}".format(Rsds.Data1, Rsds.Data2, Rsds.Data3, bytes(Rsds.Data4).hex(), Rsds.Age))

        return os.path.join(self.path, module, uuid, module)

    def SymGetLoadedModuleByAddress(self, Address):

        for name, module in self.loaded_modules.items():
            if module['Address'] <= Address < (module['Address'] + module['Size']): 
                return module
        return None

    def SymDownloadPdbFile(self, pdb):

        self.logger.debug('Downloading: Pdb: %s', pdb)
        pdburi = pdb.replace(self.path, '')
        pdburi = pdburi.replace('\\', '/')
        url = 'http://msdl.microsoft.com/' + 'download/symbols' + pdburi
        headers = {'User-Agent': 'Microsoft-Symbol-Server/10.0.10522.521'}
        response = requests.get(url, headers=headers)
        if response.status_code != 200: return False
        path = os.path.split(pdb)[0]
        os.makedirs(path, exist_ok=True)
        open(pdb, 'wb').write(response.content)

        return True

    def SymLoadModules(self, mods):

        for pdbname, base, imagesize in mods:
            self.logger.debug('pdbname: %s, base: %x', pdbname, base)

            basename = os.path.basename(pdbname)

            module = os.path.splitext(basename)[0]
            self.logger.debug('basename: %s, module: %s', basename, module)

            if module == 'ntkrnlmp': module = 'nt'
            if module == 'wkernel32': module = 'kernel32'
            if module == 'wkernelbase': module = 'kernelbase'
            if module == 'wntdll': module = 'ntdll'
            if module in self.loaded_modules:
                if pdbname == self.loaded_modules[module]['Path'] and base == self.loaded_modules[module]['Base']: continue
                else:
                    Status = self.dbghelp.SymUnloadModule64(self.hProcess, ctypes.c_int64(self.loaded_modules[module]['Base']))
                    self.logger.debug('SymUnloadModule64: module: %s, basename: %s, Pdb: %s, Base: %x', module, basename, self.loaded_modules[module]['Path'], self.loaded_modules[module]['Base'])

                    '''
                        Invalidate the previous direct reverse cache 
                    '''
                    _cache_copy = self._cache.copy()
                    for cached_key, cached_value in _cache_copy.items():
                        if isinstance(cached_key, str) and module.lower() in cached_key.lower(): 
                            del self._cache[cached_key]
                        if isinstance(cached_value, str) and module.lower() in cached_value.lower(): 
                            del self._cache[cached_key]

            if not os.path.exists(pdbname) and not self.SymDownloadPdbFile(pdbname):
                raise Exception('SymLoadModuleError: {} not found'.format(pdbname))

            address = self.dbghelp.SymLoadModuleEx(self.hProcess, None, pdbname.encode('utf8'), module.encode('utf8'), ctypes.c_int64(base), 0, None, 0)
            if not address:
                raise Exception('SymLoadModuleExError: {}'.format(pdbname))
            else:
                self.loaded_modules[module] = {'Address': address, 'Path': pdbname, 'Base': base, 'Size': imagesize}
                self.logger.debug('SymLoadModules: module: %s, basename: %s, Address: %x, Pdb: %s, Base: %x', module, basename, address, pdbname, base)

    def LookupByName(self, symbol):

        self.logger.debug('LookupByName:symbol: %s', symbol)

        if symbol.find('!') == -1: symbol = 'nt!' + symbol

        if symbol in self._cache.keys():
            self.logger.debug('LookupByName:symbol in cache: Symbol: %s, Value: %x', symbol, self._cache[symbol])
            return self._cache[symbol]

        SymbolInfo = self.SYM_INFO()
        SymbolInfo.SizeOfStruct = 88

        if not self.dbghelp.SymFromName(self.hProcess, symbol.encode('utf8'), ctypes.byref(SymbolInfo)):
            raise Exception('LookupByNameError: {}'.format(symbol))
            return None

        else:
            self._cache[symbol] = SymbolInfo.Address
            self._cache[SymbolInfo.Address] = symbol
            self.logger.debug('LookupByName:SymbolInfo.Address: Symbol: %s, Address: %x', symbol, SymbolInfo.Address)
            return SymbolInfo.Address

    def LookupByAddr(self, Address, ModuleBase=None):
        ''' \brief Lookup the requested addres in its symbol
            \remark If the ModuleBase is not given, then this function lookup the address
            only from the cache that should be filled by LookupByName
        '''
        @ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(Symbol.SYM_INFO), ctypes.c_ulong, ctypes.py_object)
        def Callback(SymInfo, SymbolSize, UserContext):

            UserContext[SymInfo[0].Address] = SymInfo[0].Name
            return True

        if Address in self._cache: return self._cache[Address]

        if not ModuleBase:
            for module, info in self.loaded_modules.items():
                if info['Address'] < Address < info['Address'] + info['Size']:
                    ModuleBase = info['Address']
                    ModuleName = module
                    break

        if not ModuleBase: return None        

        UserContext = {}
        Status = self.dbghelp.SymEnumSymbols(self.hProcess, ctypes.c_uint64(ModuleBase), "*".encode('utf8'), Callback, UserContext)

        if Status:
            for addr in UserContext:
                if addr in self._cache: continue
                self._cache[addr] = '%s!%s' % ( ModuleName, UserContext[addr].decode('utf8') )
        
        if Address in self._cache: return self._cache[Address] 
        else: return None

    def SymGetModuleByAddress(self, Address):

        for module in self.loaded_modules:

            ModuleBase = self.loaded_modules[module]['Address']
            ModuleSize = self.loaded_modules[module]['Size']

            if ModuleBase < Address < ModuleBase + ModuleSize: return module

        return None

    def SymGetModuleBase(self, Module):

        if Module not in self.loaded_modules: return None
        return self.loaded_modules[Module]['Address']

    def GetStructureMemberOffset(self, TypeName, FieldName):

        symbol = '%s+%s' % (TypeName, FieldName)
        if symbol in self._cache.keys(): return self._cache[symbol]

        ModuleName, TypeName = TypeName.split('!')
        ModuleName = ModuleName
        hModule = self.loaded_modules[ModuleName]['Address']

        self.logger.debug('GetStructureMemberOffset:ModuleName: %s', ModuleName)
        self.logger.debug('GetStructureMemberOffset:TypeName: %s', TypeName)
        self.logger.debug('GetStructureMemberOffset:hModule: %x', hModule)

        SymbolInfo = self.SYM_INFO()
        SymbolInfo.SizeOfStruct = 88

        bStatus = self.dbghelp.SymGetTypeFromName(self.hProcess, ctypes.c_uint64(hModule), TypeName.encode('utf8'), ctypes.byref(SymbolInfo))

        dwChildrenCount = ctypes.c_uint32()
        bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), SymbolInfo.TypeIndex, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_CHILDRENCOUNT, ctypes.byref(dwChildrenCount))

        class TI_FINDCHILDREN_PARAMS(ctypes.Structure):
            _fields_ = [("Count", ctypes.c_uint32),
                        ("Start", ctypes.c_uint32),
                        ("ChildId", ctypes.c_uint32 * dwChildrenCount.value)]

        ArrayChildrenParams = TI_FINDCHILDREN_PARAMS()
        ArrayChildrenParams.Count = dwChildrenCount.value
        bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), SymbolInfo.TypeIndex, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_FINDCHILDREN, ctypes.byref(ArrayChildrenParams))

        for ChildIndex in range(ArrayChildrenParams.Count):

            ChildId = ArrayChildrenParams.ChildId[ChildIndex]
            pwChildName = ctypes.c_wchar_p()

            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), ChildId, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_SYMNAME, ctypes.byref(pwChildName))

            if FieldName != pwChildName.value: continue

            dwOffset = ctypes.c_uint32()
            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), ChildId, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_OFFSET, ctypes.byref(dwOffset))

            self._cache[symbol] = dwOffset.value

            return dwOffset.value

    def EnumStructure(self, TypeName):

        class SymbolDefinition():
            def __init__(self):
                self.IsPointer = False

        if TypeName in self._cache.keys(): return self._cache[TypeName]

        OriginalTypeName = TypeName
        ModuleName, TypeName = TypeName.split('!')
        ModuleName = ModuleName
        hModule = self.loaded_modules[ModuleName]['Address']

        self.logger.debug('EnumStructure:ModuleName: %s', ModuleName)
        self.logger.debug('EnumStructure:TypeName: %s', TypeName)
        self.logger.debug('EnumStructure:hModule: %x', hModule)

        SymbolInfo = self.SYM_INFO()
        SymbolInfo.SizeOfStruct = 88

        bStatus = self.dbghelp.SymGetTypeFromName(self.hProcess, ctypes.c_uint64(hModule), TypeName.encode('utf8'), ctypes.byref(SymbolInfo))

        dwChildrenCount = ctypes.c_uint32()
        bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), SymbolInfo.TypeIndex, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_CHILDRENCOUNT, ctypes.byref(dwChildrenCount))

        class TI_FINDCHILDREN_PARAMS(ctypes.Structure):
            _fields_ = [("Count", ctypes.c_uint32),
                        ("Start", ctypes.c_uint32),
                        ("ChildId", ctypes.c_uint32 * dwChildrenCount.value)]

        ArrayChildrenParams = TI_FINDCHILDREN_PARAMS()
        ArrayChildrenParams.Count = dwChildrenCount.value
        bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), SymbolInfo.TypeIndex, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_FINDCHILDREN, ctypes.byref(ArrayChildrenParams))

        DataType = {}

        for ChildIndex in range(ArrayChildrenParams.Count):

            SymbolInfo = SymbolDefinition()

            ChildId = ArrayChildrenParams.ChildId[ChildIndex]
            pwChildName = ctypes.c_wchar_p()
            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), ChildId, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_SYMNAME, ctypes.byref(pwChildName))
            SymbolInfo.Name = pwChildName.value

            dwType = ctypes.c_uint32()
            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), ChildId, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_TYPE, ctypes.byref(dwType))
            SymbolInfo.Type = dwType.value

            dwTypeId = ctypes.c_uint32()
            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), ChildId, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_TYPEID, ctypes.byref(dwTypeId))
            SymbolInfo.TypeId = dwTypeId.value

            dwSymTag = ctypes.c_uint32()
            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), dwTypeId.value, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_SYMTAG, ctypes.byref(dwSymTag))
            SymbolInfo.SymTag = dwSymTag.value

            pwTypeName = ctypes.c_wchar_p()
            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), dwTypeId.value, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_SYMNAME, ctypes.byref(pwTypeName))
            SymbolInfo.TypeName = pwTypeName.value

            dwLength = ctypes.c_uint64()
            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), dwType.value, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_LENGTH, ctypes.byref(dwLength))
            SymbolInfo.Length = dwLength.value

            FieldName = pwChildName.value
            symbol = '%s+%s' % (TypeName, FieldName)
            SymbolInfo.Symbol = symbol

            dwOffset = ctypes.c_uint32()
            bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), ChildId, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_OFFSET, ctypes.byref(dwOffset))
            SymbolInfo.Offset = dwOffset.value

            if self.SymTagEnum[SymbolInfo.SymTag] == 'SymTagPointerType':
                bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), dwTypeId.value, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_TYPEID, ctypes.byref(dwTypeId))

                pwTypeName = ctypes.c_wchar_p()
                bStatus = self.dbghelp.SymGetTypeInfo(self.hProcess, ctypes.c_uint64(hModule), dwTypeId.value, self.IMAGEHLP_SYMBOL_TYPE_INFO.TI_GET_SYMNAME, ctypes.byref(pwTypeName))

                if bStatus:
                    SymbolInfo.IsPointer = True
                    SymbolInfo.TypeName = pwTypeName.value

            self._cache[symbol] = dwOffset.value

            '''
                Store the parsed PDB type into a dictionary with the member field offset as key and the name and the length
                We keep only the field encountered field member, in other words, we ignore any further union field.
                But we take care of the length of the biggest member. We handle only the union size in forward, not in
                backward
            '''
            if dwOffset.value not in DataType:
                DataType[SymbolInfo.Offset] = SymbolInfo
                self.logger.debug('EnumStructure: [+%#.3x] %s (%x)', SymbolInfo.Offset, SymbolInfo.Name, SymbolInfo.Length)
                LastOffset = SymbolInfo.Offset

        self._cache[OriginalTypeName] = (TypeName, DataType)
        return (TypeName, DataType)

    def PdbBuildImageOptionalHeader32(self):

        if '_IMAGE_OPTIONAL_HEADER64' not in self._cache_ctypes: return None

        _fields_ = []
        for name, ctype in self._cache_ctypes['_IMAGE_OPTIONAL_HEADER64']._fields_:

            if name == 'ImageBase':
                _fields_.append(('BaseOfData', ctypes.c_ulong))
                _fields_.append((name, ctypes.c_ulong))

            elif ctype == ctypes.c_ulonglong:
                _fields_.append((name, ctypes.c_ulong))

            else: _fields_.append((name, ctype))

        __ctypes = type('nt!_IMAGE_OPTIONAL_HEADER32', (ctypes.Structure,), {'_pack_': 1, '_fields_': _fields_})

        return __ctypes

    def PdbToCTypes(self, TypeName):

        def __ctypes__repr__(self):
            _d = {}
            for k, _ in self._fields_: _d[k] = getattr(self, k)
            return str(_d)

        def __ctypes__dump__(self):
            _d = {}
            for k, _ in self._fields_: _d[k] = getattr(self, k)
            return _d

        TypeName, DataType = self.EnumStructure(TypeName)

        if TypeName in self._cache_ctypes: return self._cache_ctypes[TypeName]
        elif TypeName == '_IMAGE_OPTIONAL_HEADER32':
            
            _ctypes = self.PdbBuildImageOptionalHeader32()

            if _ctypes is not None:
                self._cache_ctypes[TypeName] = _ctypes
                return _ctypes
            else: return None

        if not DataType:
            self._cache_ctypes[TypeName] = None
            return None

        OrderedKeys = list(DataType.keys())
        OrderedKeys.sort()

        _fields_ = []

        CurrentOffset = 0

        for Offset in OrderedKeys:

            SymbolInfo = DataType[Offset]

            if   SymbolInfo.Length == 1: ctypes_type = ctypes.c_uint8
            elif SymbolInfo.Length == 2: ctypes_type = ctypes.c_uint16
            elif SymbolInfo.Length == 4: ctypes_type = ctypes.c_uint32
            elif SymbolInfo.Length == 8: ctypes_type = ctypes.c_uint64
            else: ctypes_type = ctypes.c_uint8 * SymbolInfo.Length

            if CurrentOffset != Offset:
                ctypes_padding = ctypes.c_uint8 * (Offset-CurrentOffset)
                _fields_.append(('Padding_%x' % CurrentOffset, ctypes_padding))
                CurrentOffset = Offset

            _fields_.append((SymbolInfo.Name, ctypes_type))

            CurrentOffset += SymbolInfo.Length

        __ctypes = type(TypeName, (ctypes.Structure,), {'_pack_': 1, '_fields_': _fields_})
        setattr(__ctypes, '__repr__', __ctypes__repr__)
        setattr(__ctypes, 'dump', __ctypes__dump__)

        self._cache_ctypes[TypeName] = __ctypes

        return __ctypes

    def SymGetMemberSymbolInfo(self, TypeName, MemberName):

        TypeName, DataType = self.EnumStructure(TypeName)

        for SymbolInfo in DataType.values():
            if SymbolInfo.Name != MemberName: continue
            return SymbolInfo
