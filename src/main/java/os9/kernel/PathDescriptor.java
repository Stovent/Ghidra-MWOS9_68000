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

/**
 * @author Stovent
 */
public class PathDescriptor implements StructConverter {
    public static final String NAME = "Path Descriptor";

    public PathDescriptor(ByteProvider provider) throws IOException {
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

        struct.add(new ArrayDataType(StructConverter.BYTE, 86, -1), "PD_FST", null);

        struct.add(new ArrayDataType(StructConverter.BYTE, 128, -1), "PD_OPT", null); // 0x80

        return struct;
    }

    public static StructureDataType commonStaticDataType() {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(new UnsignedShortDataType(), "PD_PD", null); // 0x00
        struct.add(new ByteDataType(), "PD_MOD", null);
        struct.add(new ByteDataType(), "PD_CNT", null);
        struct.add(new Pointer32DataType(DeviceTableEntry.staticDataType()), "PD_DEV", null);
        struct.add(new UnsignedShortDataType(), "PD_CPR", null);
        struct.add(new Pointer32DataType(RegisterStack.staticDataType()), "PD_RGS", null);
        struct.add(new UnsignedIntegerDataType(), "PD_BUF", null);

        struct.add(new UnsignedIntegerDataType(), "PD_USER", null); // 0x12
        struct.add(new UnsignedIntegerDataType(), "PD_PATHS", null);
        struct.add(new UnsignedShortDataType(), "PD_COUNT", null);
        struct.add(new UnsignedShortDataType(), "PD_LProc", null);
        struct.add(new UnsignedShortDataType(), "unused", null);

        struct.add(new UnsignedIntegerDataType(), "PD_ErrNo", null); // 0x20
        struct.add(new Pointer32DataType(SystemGlobals.staticDataType()), "PD_SysGlob", null);
        struct.add(new UnsignedShortDataType(), "reserved", null);

        return struct;
    }
}
