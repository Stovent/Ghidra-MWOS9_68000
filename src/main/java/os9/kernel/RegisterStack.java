/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
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
public class RegisterStack implements StructConverter {
    public static final String NAME = "Register Stack";

    public RegisterStack(ByteProvider provider) throws IOException {
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

        struct.add(new ArrayDataType(new UnsignedIntegerDataType(), 8, -1), "D", null);
        struct.add(new ArrayDataType(new Pointer32DataType(), 8, -1), "A", null);
        struct.add(new UnsignedShortDataType(), "SR", null);
        struct.add(new UnsignedIntegerDataType(), "PC", null);
        struct.add(new UnsignedIntegerDataType(), "SSP", null);
        struct.add(new UnsignedIntegerDataType(), "USP", null);
        struct.add(new UnsignedIntegerDataType(), "ISP", null);
        struct.add(new UnsignedIntegerDataType(), "MSP", null);
        struct.add(new UnsignedIntegerDataType(), "VBR", null);
        struct.add(new UnsignedIntegerDataType(), "CACR", null);
        struct.add(new UnsignedIntegerDataType(), "CAAR", null);
        struct.add(new UnsignedIntegerDataType(), "SFC", null);
        struct.add(new UnsignedIntegerDataType(), "DFC", null);
        struct.add(new UnsignedShortDataType(), "unused", null);

        return struct;
    }
}
