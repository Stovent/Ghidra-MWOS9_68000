/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.util.exception.DuplicateNameException;

import os9.module.ModuleHeader;

/**
 * @author Stovent
 */
public class ProcessDescriptor implements StructConverter {
    public static final String NAME = "Process Descriptor";

    public ProcessDescriptor(ByteProvider provider) throws IOException {
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

        struct.add(new UnsignedShortDataType(), "P$ID", null); // 0x000
        struct.add(new UnsignedShortDataType(), "P$PID", null);
        struct.add(new UnsignedShortDataType(), "P$SID", null);
        struct.add(new UnsignedShortDataType(), "P$CID", null);
        struct.add(new Pointer32DataType(StructConverter.BYTE), "P$sp", null);
        struct.add(new Pointer32DataType(StructConverter.BYTE), "P$usp", null);

        struct.add(new UnsignedIntegerDataType(), "P$MemSiz", null); // 0x010
        struct.add(new UnsignedIntegerDataType(), "P$User", null);
        struct.add(new UnsignedShortDataType(), "P$Prior", null);
        struct.add(new UnsignedShortDataType(), "P$Age", null);
        struct.add(new UnsignedShortDataType(), "P$State", null);
        struct.add(new UnsignedShortDataType(), "P$Task", null);

        struct.add(new ByteDataType(), "P$QueuID", null); // 0x020
        struct.add(new ByteDataType(), "P$SCall", null);
        struct.add(new ByteDataType(), "P$Baked", null);
        struct.add(new ByteDataType());
        struct.add(new UnsignedShortDataType(), "P$DeadLk", null);
        struct.add(new UnsignedShortDataType(), "P$Signal", null);
        struct.add(new Pointer32DataType(), "P$SigVec", null);
        struct.add(new Pointer32DataType(), "P$SigDat", null);

        struct.add(new Pointer32DataType(), "P$QueueN", null); // 0x030
        struct.add(new Pointer32DataType(), "P$QueueP", null);
        struct.add(new Pointer32DataType(ModuleHeader.commonStaticDataType()), "P$PModul", null);
        struct.add(new ArrayDataType(new Pointer32DataType(StructConverter.VOID), 10, -1), "P$Except", null);

        struct.add(new ArrayDataType(new Pointer32DataType(StructConverter.VOID), 10, -1), "P$ExStk", null); // 0x064

        struct.add(new ArrayDataType(new Pointer32DataType(ModuleHeader.commonStaticDataType()), 15, -1), "P$Traps", null); // 0x08C

        struct.add(new ArrayDataType(new Pointer32DataType(StructConverter.VOID), 15, -1), "P$TrpMem", null); // 0x0C8

        struct.add(new ArrayDataType(new UnsignedIntegerDataType(), 15, -1), "P$TrpSiz", null); // 0x104

        struct.add(new Pointer32DataType(StructConverter.VOID), "P$ExcpSP", null); // 0x140
        struct.add(new Pointer32DataType(StructConverter.VOID), "P$ExcpPC", null);
        struct.add(new ArrayDataType(StructConverter.BYTE, 32, -1), "P$DIO", null);

        struct.add(new ArrayDataType(new UnsignedShortDataType(), 32, -1), "P$Path", null); // 0x168

        struct.add(new ArrayDataType(new Pointer32DataType(StructConverter.VOID), 32, -1), "P$MemImg", null); // 0x1A8

        struct.add(new ArrayDataType(new UnsignedIntegerDataType(), 32, -1), "P$BlkSiz", null); // 0x228

        struct.add(new Pointer32DataType(StructConverter.VOID), "P$DbgReg", null); // 0x2A8
        struct.add(new Pointer32DataType(StructConverter.VOID), "P$DbgPar", null);

        struct.add(new UnsignedIntegerDataType(), "P$DbgIns", null); // 0x2B0
        struct.add(new UnsignedIntegerDataType(), "P$UTicks", null);
        struct.add(new UnsignedIntegerDataType(), "P$STicks", null);
        struct.add(new UnsignedIntegerDataType(), "P$DatBeg", null);

        struct.add(new UnsignedIntegerDataType(), "P$TimBeg", null); // 0x2C0
        struct.add(new UnsignedIntegerDataType(), "P$FCalls", null);
        struct.add(new UnsignedIntegerDataType(), "P$ICalls", null);
        struct.add(new UnsignedIntegerDataType(), "P$RBytes", null);

        struct.add(new UnsignedIntegerDataType(), "P$WBytes", null); // 0x2D0
        struct.add(new UnsignedShortDataType(), "P$IOQP", null);
        struct.add(new UnsignedShortDataType(), "P$IOQN", null);
        struct.add(new UnsignedIntegerDataType(), "P$Frags1", null);
        struct.add(new UnsignedIntegerDataType(), "P$Frags2", null);

        struct.add(new UnsignedIntegerDataType(), "P$Sched", null); // 0x2E0
        struct.add(new Pointer32DataType(StructConverter.VOID), "P$SPUMem", null);
        struct.add(new UnsignedIntegerDataType(), "P$BkPtCnt", null);
        struct.add(new ArrayDataType(new UnsignedShortDataType(), 16, -1), "P$BkPts", null);

        struct.add(new ArrayDataType(new UnsignedIntegerDataType(), 8, -1), "P$Acct", null); // 0x30C

        struct.add(new Pointer32DataType(StructConverter.BYTE), "P$Data", null); // 0x32C

        struct.add(new UnsignedIntegerDataType(), "P$DataSz", null); // 0x330
        struct.add(new Pointer32DataType(StructConverter.BYTE), "P$FPUSave", null);
        struct.add(new ArrayDataType(new Pointer32DataType(StructConverter.VOID), 7, -1), "P$FPExcpt", null);

        struct.add(new ArrayDataType(new Pointer32DataType(StructConverter.VOID), 7, -1), "P$FPExStk", null); // 0x354

        struct.add(new ByteDataType(), "P$SigLvl", null); // 0x370
        struct.add(new ByteDataType(), "P$SigFlg", null);
        struct.add(new UnsignedShortDataType(), "P$Sigxs", null);
        struct.add(new UnsignedIntegerDataType(), "P$SigMask", null);
        struct.add(new UnsignedIntegerDataType(), "P$SigCnt", null);
        struct.add(new Pointer32DataType(StructConverter.VOID), "P$SigQue", null);

        struct.add(new ArrayDataType(new UnsignedIntegerDataType(), 4, -1), "P$DefSig", null); // 0x380

        // TODO: struct.
        struct.add(new Pointer32DataType(StructConverter.VOID), "P$ThreadFirst", null); // 0x390
        struct.add(new Pointer32DataType(StructConverter.VOID), "P$ThreadLast", null);
        struct.add(new Pointer32DataType(StructConverter.VOID), "P$fragFirst", null);
        struct.add(new Pointer32DataType(StructConverter.VOID), "P$fragLast", null);

        struct.add(new UnsignedIntegerDataType(), "P$MOwn", null); // 0x3A0
        struct.add(new UnsignedIntegerDataType()); // reserved
        struct.add(new UnsignedIntegerDataType()); // reserved
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x454, -1), "P$SysStk", null);

        return struct;
    }
}
