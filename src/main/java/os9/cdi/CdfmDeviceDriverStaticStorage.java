/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.cdi;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.InvalidNameException;

import os9.cdi.CdfmDriveTable;
import os9.kernel.CommonDeviceStaticStorage;
import os9.util.DataTypes;

/**
 * @author Stovent
 */
public class CdfmDeviceDriverStaticStorage implements StructConverter {
    public static final String NAME = "CDFM Device Driver Static Storage";

    public static final long V_NDRV_OFFSET = 46;

    public final int m_ndrv;

    public CdfmDeviceDriverStaticStorage(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, false); // Big-endian

        m_ndrv = reader.readUnsignedByte(V_NDRV_OFFSET);
    }

    public static String getName() {
        return NAME;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = CommonDeviceStaticStorage.staticDataType();
        try {
            struct.setNameAndCategory(new CategoryPath("/CDI"), NAME);
        }
        catch(InvalidNameException e) {} // Should not happen.

        struct.add(DataTypes.U8, "V_NDRV", "Number of drives");
        struct.add(DataTypes.U8, "V_NAP", "Number of Audio Processors");
        struct.add(DataTypes.u8Array(6), "reserved", null);
        struct.add(DataTypes.array(CdfmDriveTable.staticDataType(), m_ndrv), "V_DRVTBL", "Array of Drive tables");

        return struct;
    }

    /** Returns a static data type that assumes there is a single drive. */
    public static StructureDataType singleStaticDataType() {
        StructureDataType struct = CommonDeviceStaticStorage.staticDataType();
        try {
            struct.setNameAndCategory(new CategoryPath("/CDI"), "CDFM Device Driver Static Storage (single drive)");
        }
        catch(DuplicateNameException | InvalidNameException e) {} // Should not happen.

        struct.add(DataTypes.U8, "V_NDRV", "Number of drives");
        struct.add(DataTypes.U8, "V_NAP", "Number of Audio Processors");
        struct.add(DataTypes.u8Array(6), "reserved", null);
        struct.add(CdfmDriveTable.staticDataType(), "V_DRVTBL", "The Drive table (made-up field name)");

        return struct;
    }
}
