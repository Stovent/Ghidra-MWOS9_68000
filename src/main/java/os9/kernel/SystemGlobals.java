/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import os9.util.DataTypes;

/**
 * @author Stovent
 */
public class SystemGlobals implements StructConverter {
    public static final String NAME = "System Globals";

    public SystemGlobals() {
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
    public static StructureDataType staticDataType() {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(DataTypes.U16, "D_ID", null); // 0x000
        struct.add(DataTypes.U16, "D_NoSleep", null);
        struct.add(DataTypes.u8Array(0x1C), "", null);

        struct.add(DataTypes.U32, "D_Init", null); // 0x020 // Module*
        struct.add(DataTypes.U32, "D_Clock", null);
        struct.add(DataTypes.U16, "D_TckSec", null);
        struct.add(DataTypes.U16, "D_Year", null);
        struct.add(DataTypes.U8, "D_Month", null);
        struct.add(DataTypes.U8, "D_Day", null);
        struct.add(DataTypes.U8, "D_Compat", null);
        struct.add(DataTypes.U8, "D_68881", null);

        struct.add(DataTypes.U32, "D_Julian", null); // 0x030
        struct.add(DataTypes.U32, "D_Second", null);
        struct.add(DataTypes.u8Array(0x02), "", null);
        struct.add(DataTypes.U8, "D_IRQFlag", null);
        struct.add(DataTypes.U8, "D_UnkIRQ", null);
        struct.add(DataTypes.U32, "D_ModDir", null); // pointer

        struct.add(DataTypes.U32, "D_ModDirEnd", null); // 0x040
        struct.add(DataTypes.U32, "D_PrcDBT", null); // pointer
        struct.add(DataTypes.U32, "D_PthDBT", null); // pointer
        struct.add(DataTypes.U32, "D_Proc", null); // pointer

        struct.add(DataTypes.U32, "D_SysPrc", null); // 0x050 // pointer
        struct.add(DataTypes.U32, "D_Ticks", null);
        struct.add(DataTypes.U32, "D_FProc", null);
        struct.add(DataTypes.U32, "D_AbtStk", null);

        struct.add(DataTypes.U32, "D_SysStk", null); // 0x060
        struct.add(DataTypes.U32, "D_SysROM", null);
        struct.add(DataTypes.U32, "D_ExcJmp", null); // pointer
        struct.add(DataTypes.U32, "D_TotRAM", null);

        struct.add(DataTypes.U32, "D_MinBlk", null); // 0x070
        struct.add(DataTypes.u8Array(0x08), "", null);
        struct.add(DataTypes.U32, "D_BlkSiz", null);

        struct.add(DataTypes.U32, "D_DevTbl", null); // 0x080
        struct.add(DataTypes.u8Array(0x04), "", null);
        for(int i = 0; i < 7; i++) {
            struct.add(DataTypes.U32, "D_AutIRQ2_" + i, null);
        }
        // 0x0A4
        for(int i = 0; i < 192; i++) {
            struct.add(DataTypes.U32, "D_VctIRQ_" + i, null);
        }

        struct.add(DataTypes.U32, "D_SysDis", null); // 0x3A4
        struct.add(DataTypes.U32, "D_UsrDis", null);
        struct.add(DataTypes.U32, "D_ActivQ", null);

        struct.add(DataTypes.U32, "D_ActivQLast", null); // 0x3B0
        struct.add(DataTypes.U32, "D_SleepQ", null);
        struct.add(DataTypes.U32, "D_SleepQLast", null);
        struct.add(DataTypes.U32, "D_WaitQ", null);

        struct.add(DataTypes.U32, "D_WaitQLast", null); // 0x3C0
        struct.add(DataTypes.U32, "D_ActAge", null);
        struct.add(DataTypes.U32, "D_MPUTyp", null);
        struct.add(DataTypes.U32, "D_EvTbl", null);

        struct.add(DataTypes.U32, "D_EvTblEnd", null); // 0x3D0
        struct.add(DataTypes.U32, "D_EvID", null);
        struct.add(DataTypes.U32, "D_SPUMem", null);
        struct.add(DataTypes.U32, "D_AddrLim", null);

        struct.add(DataTypes.U8, "D_Compat2", null); // 0x3E0
        struct.add(DataTypes.U8, "D_SnoopD", null);
        struct.add(DataTypes.U16, "D_ProcSz", null);
        for(int i = 0; i < 8; i++) {
            struct.add(DataTypes.U32, "D_PolTbl", null);
        }

        struct.add(DataTypes.U32, "D_FreeMem", null); // 0x404
        struct.add(DataTypes.U32, "D_FreeMemLast", null);
        struct.add(DataTypes.U16, "D_IPID", null);
        struct.add(DataTypes.U16, "", null);

        struct.add(DataTypes.U32, "D_CPUs", null); // 0x410
        struct.add(DataTypes.U32, "D_IPCmd", null);
        struct.add(DataTypes.U32, "D_IPCmdEnd", null);
        struct.add(DataTypes.u8Array(0x348), "", null);

        struct.add(DataTypes.U32, "D_CachMode", null); // 0x764
        struct.add(DataTypes.U32, "D_DisInst", null);
        struct.add(DataTypes.U32, "D_DisData", null);

        struct.add(DataTypes.U32, "D_ClkMem", null); // 0x770
        struct.add(DataTypes.U16, "D_Tick", null);
        struct.add(DataTypes.U16, "D_TSlice", null);
        struct.add(DataTypes.U16, "D_Slice", null);
        struct.add(DataTypes.U16, "", null);
        struct.add(DataTypes.U32, "D_Elapse", null);

        struct.add(DataTypes.U32, "D_Thread", null); // 0x780
        struct.add(DataTypes.U32, "D_ThreadLast", null);
        struct.add(DataTypes.U32, "D_AlarTh", null);
        struct.add(DataTypes.U32, "D_AlarThLast", null);

        struct.add(DataTypes.U32, "D_SStkLm", null); // 0x790
        struct.add(DataTypes.U32, "D_Forks", null);
        struct.add(DataTypes.U32, "D_BootRAM", null);
        struct.add(DataTypes.U32, "D_FPUSize", null);

        struct.add(DataTypes.U32, "D_FPUMem", null); // 0x7A0
        struct.add(DataTypes.u8Array(256), "", null);
        struct.add(DataTypes.U16, "", null); // 0x8A4

        struct.add(DataTypes.U16, "D_MinPty", null); // 0x8A6
        struct.add(DataTypes.U16, "D_MaxAge", null);
        struct.add(DataTypes.U16, "D_Sieze", null);
        struct.add(DataTypes.U32, "D_Cigar", null);

        struct.add(DataTypes.u8Array(0x3C), "", null);

        struct.add(DataTypes.U32, "D_SysDgb", null); // 0x8EC

        struct.add(DataTypes.U32, "D_DgbMem", null); // 0x8F0
        struct.add(DataTypes.U32, "", null);
        struct.add(DataTypes.U32, "D_Cache", null);

        return struct;
    }
}
