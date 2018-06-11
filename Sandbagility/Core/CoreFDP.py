from Sandbagility.Debugger import Debugger
from PyFDP import FDP

class FDP(FDP.FDP):

    def AddBreakpoint(self, address, ID, cr3):
        """ Set software breakpoint at address return breakpoint ID """
        if cr3 is None: cr3 = FDP.FDP_NO_CR3
        return super(FDP, self).SetBreakpoint(FDP.FDP_SOFTHBP, ID, FDP.FDP_EXECUTE_BP, FDP.FDP_VIRTUAL_ADDRESS, address, 1, cr3)

    def SetMemoryBreakpoint(self, Target, RegionSize, Protect='e', cr3=None):

        Access = 0
        if 'e' in Protect: Access |= self.FDP_EXECUTE_BP
        if 'w' in Protect: Access |= self.FDP_WRITE_BP
        if 'r' in Protect: Access |= self.FDP_READ_BP

        # self.logger.debug('SetMemoryBreakpoint: Target: %s, BaseAddress: %x, RegionSize: %x, Handler: %s, Protect: %s, Access: %x, cr3: %s' % (Target, BaseAddress, RegionSize, Handler, Protect, Access, cr3))

        BpId = self.SetBreakpoint(
                    self.FDP_PAGEHBP,
                    0, 
                    Access,
                    self.FDP_VIRTUAL_ADDRESS,
                    Target,
                    RegionSize,
                    self.FDP_NO_CR3
        )

        return BpId

        # self.logger.debug('SetMemoryBreakpoint: BpId: %d' % (BpId))

    def SetBreakpointHardware(self, target, dr, access, length):
        """ Set the given debug register to break on execute """

        def hw(dr, access, length):

            if length == 1: _len = 0b00
            elif length == 2: _len = 0b01
            elif length == 4: _len = 0b11
            elif length == 8: _len = 0b10

            if access == 'e': 
                if length != 1: raise Exception('HardwareBreakpointError: Execution data breakpoint too large')
                _access = 0b00
            elif access == 'w': _access = 0b01
            elif access == 'r': _access = 0b11

            dr7_loword = ( 0b1 << (2 * dr) )
            dr7_hiword = (_access << (4*dr)) | (_len << ( 2 * (dr+1)))

            return ( dr7_hiword << 16 ) | dr7_loword

        setattr(self, 'dr%.1d' % dr, target)
        self.dr7 |= hw(dr, access, length)  # access

    def UnsetBreakpointHardware(self):
        """ Unset all debug registers """

        self.dr0 = 0
        self.dr1 = 0
        self.dr2 = 0
        self.dr3 = 0
        self.dr7 = 0x400

    def Resume(self):
        """ Resume the target virtual machine execution """
        if self.GetState() & self.FDP_STATE_BREAKPOINT_HIT:
            self.SingleStep()
        return super(FDP, self).Resume()

    def WaitBreak(self):
        """ Wait for a breakpoint to be reached """
        while not self.WaitForStateChanged() & self.FDP_STATE_BREAKPOINT_HIT:
            pass

    def SetControlRegisterBreakpoint(self, cr, access):

        return super(FDP, self).SetBreakpoint(BreakpointAddress=cr,
                                              BreakpointId=0,
                                              BreakpointType=self.FDP_CRHBP,
                                              BreakpointCr3=self.FDP_NO_CR3,
                                              BreakpointAddressType=self.FDP_VIRTUAL_ADDRESS,
                                              BreakpointLength=1,
                                              BreakpointAccessType=self.FDP_WRITE_BP)
