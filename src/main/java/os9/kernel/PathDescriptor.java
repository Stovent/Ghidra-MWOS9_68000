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
public class PathDescriptor implements StructConverter {
    public static final String NAME = "Path Descriptor";

    public PathDescriptor() {
    }

    public static String getName() {
        return NAME;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    public static StructureDataType staticDataType() {
        StructureDataType struct = commonStaticDataType();

        struct.add(DataTypes.u8Array(86), "PD_FST", null);

        struct.add(DataTypes.u8Array(128), "PD_OPT", null); // 0x80

        return struct;
    }

    public static StructureDataType commonStaticDataType() {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(DataTypes.U16, "PD_PD", null); // 0x00
        struct.add(DataTypes.U8, "PD_MOD", null);
        struct.add(DataTypes.U8, "PD_CNT", null);
        struct.add(DataTypes.pointer(DeviceTableEntry.staticDataType()), "PD_DEV", null);
        struct.add(DataTypes.U16, "PD_CPR", null);
        struct.add(DataTypes.pointer(RegisterStack.staticDataType()), "PD_RGS", null);
        struct.add(DataTypes.U32, "PD_BUF", null);

        struct.add(DataTypes.U32, "PD_USER", null); // 0x12
        struct.add(DataTypes.U32, "PD_PATHS", null);
        struct.add(DataTypes.U16, "PD_COUNT", null);
        struct.add(DataTypes.U16, "PD_LProc", null);
        struct.add(DataTypes.U16, "unused", null);

        struct.add(DataTypes.U32, "PD_ErrNo", null); // 0x20
        struct.add(DataTypes.pointer(SystemGlobals.staticDataType()), "PD_SysGlob", null);
        struct.add(DataTypes.U16, "reserved", null);

        return struct;
    }
}
