/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.AbstractMap.SimpleEntry;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import os9.util.Helpers;

/**
 * System Globals.
 * @author Stovent
 */
public class SystemGlobals implements StructConverter {
    public static final String NAME = "System Globals";

    public SystemGlobals(ByteProvider provider) throws IOException {
        // BinaryReader reader = new BinaryReader(provider, false); // Big-endian
    }

    public static String getName() {
        return NAME;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    /** Properties ending with "end" means address of the last element + sizeof(element).
     * Properties ending with "last" means address of the last element.
     */
    public static DataType staticDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(new UnsignedShortDataType(), "D_ID", null); // 0x000
        struct.add(new UnsignedShortDataType(), "D_NoSleep", null);
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x1C, -1), "", null);

        struct.add(new UnsignedIntegerDataType(), "D_Init", null); // 0x020 // Module*
        struct.add(new UnsignedIntegerDataType(), "D_Clock", null);
        struct.add(new UnsignedShortDataType(), "D_TckSec", null);
        struct.add(new UnsignedShortDataType(), "D_Year", null);
        struct.add(new ByteDataType(), "D_Month", null);
        struct.add(new ByteDataType(), "D_Day", null);
        struct.add(new ByteDataType(), "D_Compat", null);
        struct.add(new ByteDataType(), "D_68881", null);

        struct.add(new UnsignedIntegerDataType(), "D_Julian", null); // 0x030
        struct.add(new UnsignedIntegerDataType(), "D_Second", null);
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x02, -1), "", null);
        struct.add(new ByteDataType(), "D_IRQFlag", null);
        struct.add(new ByteDataType(), "D_UnkIRQ", null);
        struct.add(new UnsignedIntegerDataType(), "D_ModDir", null); // pointer

        struct.add(new UnsignedIntegerDataType(), "D_ModDirEnd", null); // 0x040
        struct.add(new UnsignedIntegerDataType(), "D_PrcDBT", null); // pointer
        struct.add(new UnsignedIntegerDataType(), "D_PthDBT", null); // pointer
        struct.add(new UnsignedIntegerDataType(), "D_Proc", null); // pointer

        struct.add(new UnsignedIntegerDataType(), "D_SysPrc", null); // 0x050 // pointer
        struct.add(new UnsignedIntegerDataType(), "D_Ticks", null);
        struct.add(new UnsignedIntegerDataType(), "D_FProc", null);
        struct.add(new UnsignedIntegerDataType(), "D_AbtStk", null);

        struct.add(new UnsignedIntegerDataType(), "D_SysStk", null); // 0x060
        struct.add(new UnsignedIntegerDataType(), "D_SysROM", null);
        struct.add(new UnsignedIntegerDataType(), "D_ExcJmp", null); // pointer
        struct.add(new UnsignedIntegerDataType(), "D_TotRAM", null);

        struct.add(new UnsignedIntegerDataType(), "D_MinBlk", null); // 0x070
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x08, -1), "", null);
        struct.add(new UnsignedIntegerDataType(), "D_BlkSiz", null);

        struct.add(new UnsignedIntegerDataType(), "D_DevTbl", null); // 0x080
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x04, -1), "", null);
        for(int i = 0; i < 7; i++) {
            struct.add(new UnsignedIntegerDataType(), "D_AutIRQ2_" + i, null);
        }
        // 0x0A4
        for(int i = 0; i < 192; i++) {
            struct.add(new UnsignedIntegerDataType(), "D_VctIRQ_" + i, null);
        }

        struct.add(new UnsignedIntegerDataType(), "D_SysDis", null); // 0x3A4
        struct.add(new UnsignedIntegerDataType(), "D_UsrDis", null);
        struct.add(new UnsignedIntegerDataType(), "D_ActivQ", null);

        struct.add(new UnsignedIntegerDataType(), "D_ActivQLast", null); // 0x3B0
        struct.add(new UnsignedIntegerDataType(), "D_SleepQ", null);
        struct.add(new UnsignedIntegerDataType(), "D_SleepQLast", null);
        struct.add(new UnsignedIntegerDataType(), "D_WaitQ", null);

        struct.add(new UnsignedIntegerDataType(), "D_WaitQLast", null); // 0x3C0
        struct.add(new UnsignedIntegerDataType(), "D_ActAge", null);
        struct.add(new UnsignedIntegerDataType(), "D_MPUTyp", null);
        struct.add(new UnsignedIntegerDataType(), "D_EvTbl", null);

        struct.add(new UnsignedIntegerDataType(), "D_EvTblEnd", null); // 0x3D0
        struct.add(new UnsignedIntegerDataType(), "D_EvID", null);
        struct.add(new UnsignedIntegerDataType(), "D_SPUMem", null);
        struct.add(new UnsignedIntegerDataType(), "D_AddrLim", null);

        struct.add(new ByteDataType(), "D_Compat2", null); // 0x3E0
        struct.add(new ByteDataType(), "D_SnoopD", null);
        struct.add(new UnsignedShortDataType(), "D_ProcSz", null);
        for(int i = 0; i < 8; i++) {
            struct.add(new UnsignedIntegerDataType(), "D_PolTbl", null);
        }

        struct.add(new UnsignedIntegerDataType(), "D_FreeMem", null); // 0x404
        struct.add(new UnsignedIntegerDataType(), "D_FreeMemLast", null);
        struct.add(new UnsignedShortDataType(), "D_IPID", null);
        struct.add(new UnsignedShortDataType(), "", null);

        struct.add(new UnsignedIntegerDataType(), "D_CPUs", null); // 0x410
        struct.add(new UnsignedIntegerDataType(), "D_IPCmd", null);
        struct.add(new UnsignedIntegerDataType(), "D_IPCmdEnd", null);
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x348, -1), "", null);

        struct.add(new UnsignedIntegerDataType(), "D_CachMode", null); // 0x764
        struct.add(new UnsignedIntegerDataType(), "D_DisInst", null);
        struct.add(new UnsignedIntegerDataType(), "D_DisData", null);

        struct.add(new UnsignedIntegerDataType(), "D_ClkMem", null); // 0x770
        struct.add(new UnsignedShortDataType(), "D_Tick", null);
        struct.add(new UnsignedShortDataType(), "D_TSlice", null);
        struct.add(new UnsignedShortDataType(), "D_Slice", null);
        struct.add(new UnsignedShortDataType(), "", null);
        struct.add(new UnsignedIntegerDataType(), "D_Elapse", null);

        struct.add(new UnsignedIntegerDataType(), "D_Thread", null); // 0x780
        struct.add(new UnsignedIntegerDataType(), "D_ThreadLast", null);
        struct.add(new UnsignedIntegerDataType(), "D_AlarTh", null);
        struct.add(new UnsignedIntegerDataType(), "D_AlarThLast", null);

        struct.add(new UnsignedIntegerDataType(), "D_SStkLm", null); // 0x790
        struct.add(new UnsignedIntegerDataType(), "D_Forks", null);
        struct.add(new UnsignedIntegerDataType(), "D_BootRAM", null);
        struct.add(new UnsignedIntegerDataType(), "D_FPUSize", null);

        struct.add(new UnsignedIntegerDataType(), "D_FPUMem", null); // 0x7A0
        struct.add(new ArrayDataType(StructConverter.BYTE, 256, -1), "", null);
        struct.add(new UnsignedShortDataType(), "", null); // 0x8A4

        struct.add(new UnsignedShortDataType(), "D_MinPty", null); // 0x8A6
        struct.add(new UnsignedShortDataType(), "D_MaxAge", null);
        struct.add(new UnsignedShortDataType(), "D_Sieze", null);
        struct.add(new UnsignedIntegerDataType(), "D_Cigar", null);

        struct.add(new ArrayDataType(StructConverter.BYTE, 0x3C, -1), "", null);

        struct.add(new UnsignedIntegerDataType(), "D_SysDgb", null); // 0x8EC

        struct.add(new UnsignedIntegerDataType(), "D_DgbMem", null); // 0x8F0
        struct.add(new UnsignedIntegerDataType(), "", null);
        struct.add(new UnsignedIntegerDataType(), "D_Cache", null);

        return struct;
    }
}
