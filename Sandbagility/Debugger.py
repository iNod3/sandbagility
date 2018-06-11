
from abc import ABC, abstractmethod


class Debugger(ABC):

    @abstractmethod
    def ReadRegister(self, RegisterId):
        """ Return the value stored in the specified register
        RegisterId must be a member of FDP.FDP_REGISTER
        """
        pass

    @abstractmethod
    def WriteRegister(self, RegisterId, RegisterValue):
        """ Store the given value into the specified register
        RegisterId must be a member of FDP.FDP_REGISTER
        """
        pass

    @abstractmethod
    def ReadMsr(self, MsrId):
        """ Return the value stored in the Model-specific register (MSR) indexed by MsrId
        MSR typically don't have an enum Id since there are vendor specific.
        """
        pass

    @abstractmethod
    def WriteMsr(self, MsrId, MsrValue):
        """ Store the value into the Model-specific register (MSR) indexed by MsrId
        MSR typically don't have an enum Id since there are vendor specific.
        """
        pass

    @abstractmethod
    def Pause(self):
        """ Suspend the target virtual machine """
        pass

    @abstractmethod
    def Resume(self):
        """ Resume the target virtual machine execution """
        pass

    @abstractmethod
    def Save(self):
        """Save the virtual machine state (CPU+memory).
        Only one save state allowed.
        """
        pass

    @abstractmethod
    def WaitBreak(self):
        """ Wait for a breakpoint to be reached """
        pass

    @abstractmethod
    def Restore(self):
        """ Restore the previously stored virtual machine state (CPU+memory). """
        pass

    @abstractmethod
    def Reboot(self):
        """ Reboot the target virtual machine """
        pass

    @abstractmethod
    def SingleStep(self):
        """ Single step a paused execution """
        pass

    @abstractmethod
    def ReadVirtualMemory(self, VirtualAddress, ReadSize):
        """ Attempt to read a VM virtual memory buffer.
        Check CR3 to know which process's memory you're reading
        """
        pass

    @abstractmethod
    def ReadPhysicalMemory(self, PhysicalAddress, ReadSize):
        """ Attempt to read a VM physical memory buffer. """
        pass

    @abstractmethod
    def WritePhysicalMemory(self, PhysicalAddress, WriteBuffer):
        """ Attempt to write a buffer at a VM physical memory address. """
        pass

    @abstractmethod
    def WriteVirtualMemory(self, VirtualAddress, WriteBuffer):
        """ Attempt to write a buffer at a VM virtual memory address.
        Check CR3 to know which process's memory you're writing into.
        """
        pass

    @abstractmethod
    def SetBreakpointerHardware(self, target, dr, access, length):
        """ Set the given debug register to break on execute """
        pass

    @abstractmethod
    def UnsetBreakpointHardware(self):
        """ Unset all debug registers """
        pass

    @abstractmethod
    def SetBreakpoint(self, BreakpointType, BreakpointId, BreakpointAccessType,
                      BreakpointAddressType, BreakpointAddress, BreakpointLength, BreakpointCr3):
        """
        Place a breakpoint.

        * BreakpointType :
            - FDP.FDP_SOFTHBP : "soft" hyperbreakpoint, backed by a shadow "0xcc" instruction in the VM physical memory page. # noqa E501
            - FDP.FDP_HARDHBP : "hard" hyperbreakpoint, backed by a shadow debug register (only 4)
            - FDP.FDP_PAGEHBP : "page" hyperbreakpoint relying on Extended Page Table (EPT) page guard faults.
            - FDP.FDP_MSRHBP  : "msr" hyperbreakpoint, specifically to read a VM's MSR
            - FDP.FDP_CRHBP  : "cr" hyperbreakpoint, specifically to read a VM's Context Register

        * BreakpointId: Currently unused

        * BreakpointAccessType:
            - FDP.FDP_EXECUTE_BP : break on execution
            - FDP.FDP_WRITE_BP : break on write
            - FDP.FDP_READ_BP : break on read
            - FDP.FDP_INSTRUCTION_FETCH_BP : break when fetching instructions before executing

        * BreakpointAddressType:
            - FDP.FDP_VIRTUAL_ADDRESS : VM's virtual addressing
            - FDP.FDP_PHYSICAL_ADDRESS  : VM's physical addressing

        * BreakpointAddress: address (virtual or physical) to break execution

        * BreakpointLength: Length of the data pointed by BreakpointAddress which trigger the breakpoint (think "ba e 8" style of breakpoint)

        * BreakpointCr3: Filter breakpoint on a specific CR3 value. Mandatory if you want to break on a particular process.
        """
        pass

    @abstractmethod
    def UnsetBreakpoint(self, BreakpointId):
        """ Remove the selected breakpoint. Return True on success """
        pass

    @abstractmethod
    def GetState(self):
        """
        Return the bitfield state of an system execution break (all CPUs considered):

        - FDP.FDP_STATE_PAUSED : the VM is paused.
        - FDP.FDP_STATE_BREAKPOINT_HIT : the execution has hit a soft or page breakpoint
        - FDP.FDP_STATE_DEBUGGER_ALERTED : the VM is in a debuggable state
        - FDP.FDP_STATE_HARD_BREAKPOINT_HIT : the execution has hit a hard breakpoint
        """
        pass

    @abstractmethod
    def GetCpuState(self):
        """
        Return the bitfield state of an execution break for the specified CpuId:

        - FDP.FDP_STATE_PAUSED : the VM is paused.
        - FDP.FDP_STATE_BREAKPOINT_HIT : the execution has hit a soft or page breakpoint
        - FDP.FDP_STATE_DEBUGGER_ALERTED : the VM is in a debuggable state
        - FDP.FDP_STATE_HARD_BREAKPOINT_HIT : the execution has hit a hard breakpoint
        """
        pass

    @abstractmethod
    def GetPhysicalMemorySize(self):
        """ return the target VM physical memory size, or None on failure """
        pass

    @abstractmethod
    def GetCpuCount(self):
        """ return the target VM CPU count, or None on failure """
        pass

    @abstractmethod
    def GetStateChanged(self):
        """ check if the VM execution state has changed. Useful on resume."""
        pass

    @abstractmethod
    def WaitForStateChanged(self):
        """ wait for the VM execution state has change. Useful on when waiting for a breakpoint to hit."""
        pass

    @abstractmethod
    def InjectInterrupt(self, InterruptionCode, ErrorCode, Cr2Value):
        """
        Inject an interruption in the VM execution state.

        * InterruptionCode (int) : interrupt code (e.g. 0x0E for a #PF)
        * ErrorCode : the error code for the interruption (e.g. 0x02 for a Write error on a #PF)
        * Cr2Value : typically the address associated with the interruption
        """
        pass

    @abstractmethod
    def UnsetAllBreakpoint(self):
        """ Remove every set breakpoints """
        pass

    @abstractmethod
    def DumpPhysicalMemory(self, FilePath):
        """ Write the whole VM physical memory to the host disk. Useful for Volatility-like tools."""
        pass
