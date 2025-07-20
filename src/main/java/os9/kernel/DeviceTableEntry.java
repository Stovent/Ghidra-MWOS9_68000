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
public class DeviceTableEntry implements StructConverter {
    public static final String NAME = "Device Table Entry";

    public DeviceTableEntry() {
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
        struct.add(DataTypes.VoidPointer, "V$DRIV", null);
        struct.add(DataTypes.pointer(CommonDeviceStaticStorage.staticDataType()), "V$STAT", null);
        struct.add(DataTypes.VoidPointer, "V$DESC", null); // Device Descriptor is variable-length.
        struct.add(DataTypes.VoidPointer, "V$FMGR", null);
        struct.add(DataTypes.U16, "V$USRS", null);

        return struct;
    }
}
