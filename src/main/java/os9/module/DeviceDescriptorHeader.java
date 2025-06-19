/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.module;

import java.io.IOException;

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
import os9.util.Structure;

/**
 *
 * @author Stovent
 */
public class DeviceDescriptorHeader implements Structure {
    public static final String NAME = "Device Descriptor Header";

    public static final long FMGR_OFFSET = 0x38;
    public static final long PDEV_OFFSET = 0x3A;
    public static final long DEVCON_OFFSET = 0x3C;

    public final int m_fileManager;
    public final int m_deviceDriver;
    public final int m_devCon;
    public final int m_opt;

    /** Give the same provider as the module. */
    public DeviceDescriptorHeader(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, false); // Big-endian

        m_fileManager = reader.readUnsignedShort(FMGR_OFFSET);
        m_deviceDriver = reader.readUnsignedShort(PDEV_OFFSET);
        m_devCon = reader.readUnsignedShort(DEVCON_OFFSET);
        m_opt = reader.readUnsignedShort(0x46);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
        Helpers.createString(program, moduleAddress, FMGR_OFFSET, m_fileManager);
        Helpers.createString(program, moduleAddress, PDEV_OFFSET, m_deviceDriver);
        Helpers.createReference(program, moduleAddress, DEVCON_OFFSET, m_devCon);
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(new UnsignedIntegerDataType(), "M$Port", null);
        struct.add(new ByteDataType(), "M$Vector", null);
        struct.add(new ByteDataType(), "M$IRQLvl", null);
        struct.add(new ByteDataType(), "M$Prior", null);
        struct.add(new ByteDataType(), "M$Mode", null);
        struct.add(new UnsignedShortDataType(), "M$FMgr", null);
        struct.add(new UnsignedShortDataType(), "M$PDev", null);
        struct.add(new UnsignedShortDataType(), "M$DevCon", null);
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x08, -1), "Reserved", null);
        struct.add(new UnsignedShortDataType(), "M$Opt", null);
        struct.add(new ArrayDataType(StructConverter.BYTE, m_opt, -1), "Options", null);

        // struct.add(new /* todo */DataType(), "M$DTyp", null);
        // The option section depends on the M$DTyp field.

        return struct;
    }
}
