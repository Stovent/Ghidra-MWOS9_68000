/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.module;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.Msg;
import os9.util.Helpers;
import os9.util.Structure;

/**
 *
 * @author Stovent
 */
public class TrapHandlerHeader implements Structure {
    public static final String NAME = "Trap Handler Header";

    public static final long EXEC_OFFSET = 0x30;
    public static final long EXCPT_OFFSET = 0x34;
    public static final long INIT_OFFSET = 0x48;
    public static final long TERM_OFFSET = 0x4C;

    public final long m_exec;
    public final long m_excpt;
    public final long m_init;
    public final long m_term;

    /** Give the same provider as the module. */
    public TrapHandlerHeader(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, false); // Big-endian

        m_exec = reader.readUnsignedInt(EXEC_OFFSET);
        m_excpt = reader.readUnsignedInt(EXCPT_OFFSET);
        m_init = reader.readUnsignedInt(INIT_OFFSET);
        m_term = reader.readUnsignedInt(TERM_OFFSET);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
        try {
            // The exec function is executed as if a jsr is used (OS_9 manual 5-2)
            Helpers.createFunction(program, moduleAddress, EXEC_OFFSET, m_exec, "Exec");
            Helpers.createFunction(program, moduleAddress, EXCPT_OFFSET, m_excpt, "Excpt");
            Helpers.createFunction(program, moduleAddress, INIT_OFFSET, m_init, "Init");
            Helpers.createFunction(program, moduleAddress, TERM_OFFSET, m_term, "Term");
        }
        catch(InvalidInputException | OverlappingFunctionException e) {
            Msg.showError(this, null, "TrapHandlerHeader", "Failed to create functions");
            e.printStackTrace();
        }
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    public static DataType staticDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(new UnsignedIntegerDataType(), "M$Exec", null);
        struct.add(new UnsignedIntegerDataType(), "M$Excpt", null);
        struct.add(new UnsignedIntegerDataType(), "M$Mem", null);
        struct.add(new UnsignedIntegerDataType(), "M$Stack", null);
        struct.add(new UnsignedIntegerDataType(), "M$IData", null);
        struct.add(new UnsignedIntegerDataType(), "M$IRefs", null);
        struct.add(new UnsignedIntegerDataType(), "M$Init", null);
        struct.add(new UnsignedIntegerDataType(), "M$Term", null);

        return struct;
    }
}
