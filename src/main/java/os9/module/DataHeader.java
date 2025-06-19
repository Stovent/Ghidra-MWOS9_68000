/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.module;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import os9.util.Helpers;
import os9.util.Structure;

/**
 * Data header is for data modules which have the m$Exec field pointing to the beginning of data.
 * @author Stovent
 */
public class DataHeader implements Structure {
    public static final String NAME = "Data Header";

    public static final long DATA_OFFSET = 0x30;

    public final long m_data;

    public DataHeader(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, false); // Big-endian

        m_data = reader.readUnsignedInt(DATA_OFFSET);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
        Helpers.createReference(program, moduleAddress, DATA_OFFSET, m_data);
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    public static DataType staticDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        // struct.add(new UnsignedIntegerDataType(), "M$Exec", null);
        struct.add(new UnsignedIntegerDataType(), "M$Data", null);

        return struct;
    }
}
