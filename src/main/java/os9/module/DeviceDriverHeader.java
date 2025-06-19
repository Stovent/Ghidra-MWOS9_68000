/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.module;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
// import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
// import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
// import ghidra.program.model.symbol.SourceType;
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
public class DeviceDriverHeader implements Structure {
    public static final String NAME = "Device Driver Header";

    public static final long EXEC_OFFSET = 0x30;

    public final long m_exec;
    public final EntryTable entryTable;

    public DeviceDriverHeader(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, false); // Big-endian

        m_exec = reader.readUnsignedInt(EXEC_OFFSET);
        entryTable = new EntryTable(provider, m_exec);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
        Helpers.createData(program, moduleAddress, EXEC_OFFSET, m_exec, entryTable.toDataType());
        entryTable.applyToProgram(program.getImageBase(), program);
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), getName(), 0);

        struct.add(new UnsignedIntegerDataType(), "M$Exec", null);
        struct.add(new UnsignedIntegerDataType(), "M$Excpt", null);
        struct.add(new UnsignedIntegerDataType(), "M$Mem", null);

        return struct;
    }

    public class EntryTable implements Structure {
        public static final String NAME = "Entry Table";

        public static final long INIT_OFFSET = 0x00;
        public static final long READ_OFFSET = 0x02;
        public static final long WRITE_OFFSET = 0x04;
        public static final long GETSTAT_OFFSET = 0x06;
        public static final long SETSTAT_OFFSET = 0x08;
        public static final long TERM_OFFSET = 0x0A;
        public static final long ERROR_OFFSET = 0x0C;

        public final long init;
        public final long initOffset;
        public final long read;
        public final long readOffset;
        public final long write;
        public final long writeOffset;
        public final long getStat;
        public final long getStatOffset;
        public final long setStat;
        public final long setStatOffset;
        public final long term;
        public final long termOffset;
        public final long error;
        public final long errorOffset;

        /** Creates a new ColoredMemoryStruct with the provider starting at the beginning of the module. */
        public EntryTable(ByteProvider provider, long structOffset) throws IOException {
            BinaryReader reader = new BinaryReader(provider, false); // Big-endian

            initOffset = structOffset + INIT_OFFSET;
            init = reader.readUnsignedShort(initOffset);
            readOffset = structOffset + READ_OFFSET;
            read = reader.readUnsignedShort(readOffset);
            writeOffset = structOffset + WRITE_OFFSET;
            write = reader.readUnsignedShort(writeOffset);
            getStatOffset = structOffset + GETSTAT_OFFSET;
            getStat = reader.readUnsignedShort(getStatOffset);
            setStatOffset = structOffset + SETSTAT_OFFSET;
            setStat = reader.readUnsignedShort(setStatOffset);
            termOffset = structOffset + TERM_OFFSET;
            term = reader.readUnsignedShort(termOffset);
            errorOffset = structOffset + ERROR_OFFSET;
            error = reader.readUnsignedShort(errorOffset);
        }

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
            try {
                // functionManager.createFunction("Init", moduleAddress.add(init), new AddressSet(moduleAddress.add(init)), SourceType.ANALYSIS);
                // functionManager.createFunction("Read", moduleAddress.add(read), new AddressSet(moduleAddress.add(read)), SourceType.ANALYSIS);
                // functionManager.createFunction("Write", moduleAddress.add(write), new AddressSet(moduleAddress.add(write)), SourceType.ANALYSIS);
                // functionManager.createFunction("GetStat", moduleAddress.add(getStat), new AddressSet(moduleAddress.add(getStat)), SourceType.ANALYSIS);
                // functionManager.createFunction("SetStat", moduleAddress.add(setStat), new AddressSet(moduleAddress.add(setStat)), SourceType.ANALYSIS);
                // functionManager.createFunction("Term", moduleAddress.add(term), new AddressSet(moduleAddress.add(term)), SourceType.ANALYSIS);
                // functionManager.createFunction("Error", moduleAddress.add(error), new AddressSet(moduleAddress.add(error)), SourceType.ANALYSIS);
                Helpers.createFunction(program, moduleAddress, initOffset, init, "Init");
                Helpers.createFunction(program, moduleAddress, readOffset, read, "Read");
                Helpers.createFunction(program, moduleAddress, writeOffset, write, "Write");
                Helpers.createFunction(program, moduleAddress, getStatOffset, getStat, "GetStat");
                Helpers.createFunction(program, moduleAddress, setStatOffset, setStat, "SetStat");
                Helpers.createFunction(program, moduleAddress, termOffset, term, "Term");
                Helpers.createFunction(program, moduleAddress, errorOffset, error, "Error");
            }
            catch(InvalidInputException | OverlappingFunctionException | CodeUnitInsertionException e) {
                Msg.showError(this, null, "EntryTable", "Failed to create entry table function");
                e.printStackTrace();
            }
        }

        @Override
        public DataType toDataType() {
            StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), getName(), 0);

            struct.add(new UnsignedShortDataType(), "Init", null);
            struct.add(new UnsignedShortDataType(), "Read", null);
            struct.add(new UnsignedShortDataType(), "Write", null);
            struct.add(new UnsignedShortDataType(), "GetStat", null);
            struct.add(new UnsignedShortDataType(), "SetStat", null);
            struct.add(new UnsignedShortDataType(), "Term", null);
            struct.add(new UnsignedShortDataType(), "Error", null);

            return struct;
        }
    }
}
