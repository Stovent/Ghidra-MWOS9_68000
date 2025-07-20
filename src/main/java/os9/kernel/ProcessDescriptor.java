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

import os9.module.ModuleHeader;
import os9.util.DataTypes;

/**
 * @author Stovent
 */
public class ProcessDescriptor implements StructConverter {
    public static final String NAME = "Process Descriptor";

    public ProcessDescriptor() {
    }

    public static String getName() {
        return NAME;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    public static StructureDataType staticDataType() {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(DataTypes.U16, "P$ID", null); // 0x000
        struct.add(DataTypes.U16, "P$PID", null);
        struct.add(DataTypes.U16, "P$SID", null);
        struct.add(DataTypes.U16, "P$CID", null);
        struct.add(DataTypes.U8Pointer, "P$sp", null);
        struct.add(DataTypes.U8Pointer, "P$usp", null);

        struct.add(DataTypes.U32, "P$MemSiz", null); // 0x010
        struct.add(DataTypes.U32, "P$User", null);
        struct.add(DataTypes.U16, "P$Prior", null);
        struct.add(DataTypes.U16, "P$Age", null);
        struct.add(DataTypes.U16, "P$State", null);
        struct.add(DataTypes.U16, "P$Task", null);

        struct.add(DataTypes.U8, "P$QueuID", null); // 0x020
        struct.add(DataTypes.U8, "P$SCall", null);
        struct.add(DataTypes.U8, "P$Baked", null);
        struct.add(DataTypes.U8);
        struct.add(DataTypes.U16, "P$DeadLk", null);
        struct.add(DataTypes.U16, "P$Signal", null);
        struct.add(DataTypes.VoidPointer, "P$SigVec", null);
        struct.add(DataTypes.VoidPointer, "P$SigDat", null);

        struct.add(DataTypes.VoidPointer, "P$QueueN", null); // 0x030
        struct.add(DataTypes.VoidPointer, "P$QueueP", null);
        struct.add(DataTypes.pointer(ModuleHeader.commonStaticDataType()), "P$PModul", null);
        struct.add(DataTypes.array(DataTypes.VoidPointer, 10), "P$Except", null);

        struct.add(DataTypes.array(DataTypes.VoidPointer, 10), "P$ExStk", null); // 0x064

        struct.add(DataTypes.array(DataTypes.pointer(ModuleHeader.commonStaticDataType()), 15), "P$Traps", null); // 0x08C

        struct.add(DataTypes.array(DataTypes.VoidPointer, 15), "P$TrpMem", null); // 0x0C8

        struct.add(DataTypes.u32Array(15), "P$TrpSiz", null); // 0x104

        struct.add(DataTypes.VoidPointer, "P$ExcpSP", null); // 0x140
        struct.add(DataTypes.VoidPointer, "P$ExcpPC", null);
        struct.add(DataTypes.u8Array(32), "P$DIO", null);

        struct.add(DataTypes.u16Array(32), "P$Path", null); // 0x168

        struct.add(DataTypes.array(DataTypes.VoidPointer, 32), "P$MemImg", null); // 0x1A8

        struct.add(DataTypes.u32Array(32), "P$BlkSiz", null); // 0x228

        struct.add(DataTypes.VoidPointer, "P$DbgReg", null); // 0x2A8
        struct.add(DataTypes.VoidPointer, "P$DbgPar", null);

        struct.add(DataTypes.U32, "P$DbgIns", null); // 0x2B0
        struct.add(DataTypes.U32, "P$UTicks", null);
        struct.add(DataTypes.U32, "P$STicks", null);
        struct.add(DataTypes.U32, "P$DatBeg", null);

        struct.add(DataTypes.U32, "P$TimBeg", null); // 0x2C0
        struct.add(DataTypes.U32, "P$FCalls", null);
        struct.add(DataTypes.U32, "P$ICalls", null);
        struct.add(DataTypes.U32, "P$RBytes", null);

        struct.add(DataTypes.U32, "P$WBytes", null); // 0x2D0
        struct.add(DataTypes.U16, "P$IOQP", null);
        struct.add(DataTypes.U16, "P$IOQN", null);
        struct.add(DataTypes.U32, "P$Frags1", null);
        struct.add(DataTypes.U32, "P$Frags2", null);

        struct.add(DataTypes.U32, "P$Sched", null); // 0x2E0
        struct.add(DataTypes.VoidPointer, "P$SPUMem", null);
        struct.add(DataTypes.U32, "P$BkPtCnt", null);
        struct.add(DataTypes.u16Array(16), "P$BkPts", null);

        struct.add(DataTypes.u32Array(8), "P$Acct", null); // 0x30C

        struct.add(DataTypes.U8Pointer, "P$Data", null); // 0x32C

        struct.add(DataTypes.U32, "P$DataSz", null); // 0x330
        struct.add(DataTypes.U8Pointer, "P$FPUSave", null);
        struct.add(DataTypes.array(DataTypes.VoidPointer, 7), "P$FPExcpt", null);

        struct.add(DataTypes.array(DataTypes.VoidPointer, 7), "P$FPExStk", null); // 0x354

        struct.add(DataTypes.U8, "P$SigLvl", null); // 0x370
        struct.add(DataTypes.U8, "P$SigFlg", null);
        struct.add(DataTypes.U16, "P$Sigxs", null);
        struct.add(DataTypes.U32, "P$SigMask", null);
        struct.add(DataTypes.U32, "P$SigCnt", null);
        struct.add(DataTypes.VoidPointer, "P$SigQue", null);

        struct.add(DataTypes.u32Array(4), "P$DefSig", null); // 0x380

        // TODO: struct.
        struct.add(DataTypes.VoidPointer, "P$ThreadFirst", null); // 0x390
        struct.add(DataTypes.VoidPointer, "P$ThreadLast", null);
        struct.add(DataTypes.VoidPointer, "P$fragFirst", null);
        struct.add(DataTypes.VoidPointer, "P$fragLast", null);

        struct.add(DataTypes.U32, "P$MOwn", null); // 0x3A0
        struct.add(DataTypes.U32); // reserved
        struct.add(DataTypes.U32); // reserved
        struct.add(DataTypes.u8Array(0x454), "P$SysStk", null);

        return struct;
    }
}
