/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * @author Stovent
 */
public class DeviceTableEntry implements StructConverter {
    public static final String NAME = "Device Table Entry";

    public DeviceTableEntry(ByteProvider provider) throws IOException {
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

        // Module header is variable length so not usable here.
        struct.add(new Pointer32DataType(), "V$DRIV", null);
        struct.add(new Pointer32DataType(CommonDeviceStaticStorage.staticDataType()), "V$STAT", null);
        struct.add(new Pointer32DataType(), "V$DESC", null); // Device Descriptor is variable-length.
        struct.add(new Pointer32DataType(), "V$FMGR", null);
        struct.add(new UnsignedShortDataType(), "V$USRS", null);

        return struct;
    }
}
