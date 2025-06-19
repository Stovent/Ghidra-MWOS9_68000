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
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import os9.util.Helpers;
import os9.util.Structure;

/**
 *
 * @author Stovent
 */
public class FileManagerHeader implements Structure {
    public static final String NAME = "File Manager Header";

    public static final long EXEC_OFFSET = 0x30;

    public final long m_exec;
    public final EntryTable entryTable;

    public FileManagerHeader(ByteProvider provider) throws IOException {
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
        try {
            Helpers.createData(program, moduleAddress, EXEC_OFFSET, m_exec, entryTable.toDataType());
        } catch (Exception ex) {
        }
        entryTable.applyToProgram(program.getImageBase(), program);
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        return staticDataType();
    }

    public static DataType staticDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

        struct.add(new UnsignedIntegerDataType(), "M$Exec", null);
        struct.add(new UnsignedIntegerDataType(), "M$Excpt", null);

        return struct;
    }

    public class EntryTable implements Structure {
        public static final String NAME = "Entry Table";

        public static final long CREATE_OFFSET = 0x00;
        public static final long OPEN_OFFSET = 0x02;
        public static final long MAKDIR_OFFSET = 0x04;
        public static final long CHGDIR_OFFSET = 0x06;
        public static final long DELETE_OFFSET = 0x08;
        public static final long SEEK_OFFSET = 0x0A;
        public static final long READ_OFFSET = 0x0C;
        public static final long WRITE_OFFSET = 0x0E;
        public static final long READLN_OFFSET = 0x10;
        public static final long WRITELN_OFFSET = 0x12;
        public static final long GETSTAT_OFFSET = 0x14;
        public static final long SETSTAT_OFFSET = 0x16;
        public static final long CLOSE_OFFSET = 0x18;

        public final long create;
        public final long createOffset;
        public final long open;
        public final long openOffset;
        public final long makDir;
        public final long makDirOffset;
        public final long chgDir;
        public final long chgDirOffset;
        public final long delete;
        public final long deleteOffset;
        public final long seek;
        public final long seekOffset;
        public final long read;
        public final long readOffset;
        public final long write;
        public final long writeOffset;
        public final long readLn;
        public final long readLnOffset;
        public final long writeLn;
        public final long writeLnOffset;
        public final long getStat;
        public final long getStatOffset;
        public final long setStat;
        public final long setStatOffset;
        public final long close;
        public final long closeOffset;

        /** Creates a new ColoredMemoryStruct with the provider starting at the beginning of the module.
         * For some reason unlike the device driver the fields are relative to the base of the entry table (OS-9 Guru 13.3).
         */
        public EntryTable(ByteProvider provider, long structOffset) throws IOException {
            BinaryReader reader = new BinaryReader(provider, false); // Big-endian

            createOffset = structOffset + CREATE_OFFSET;
            create = reader.readUnsignedShort(createOffset) + structOffset;
            openOffset = structOffset + OPEN_OFFSET;
            open = reader.readUnsignedShort(openOffset) + structOffset;
            makDirOffset = structOffset + MAKDIR_OFFSET;
            makDir = reader.readUnsignedShort(makDirOffset) + structOffset;
            chgDirOffset = structOffset + CHGDIR_OFFSET;
            chgDir = reader.readUnsignedShort(chgDirOffset) + structOffset;
            deleteOffset = structOffset + DELETE_OFFSET;
            delete = reader.readUnsignedShort(deleteOffset) + structOffset;
            seekOffset = structOffset + SEEK_OFFSET;
            seek = reader.readUnsignedShort(seekOffset) + structOffset;
            readOffset = structOffset + READ_OFFSET;
            read = reader.readUnsignedShort(readOffset) + structOffset;
            writeOffset = structOffset + WRITE_OFFSET;
            write = reader.readUnsignedShort(writeOffset) + structOffset;
            readLnOffset = structOffset + READLN_OFFSET;
            readLn = reader.readUnsignedShort(readLnOffset) + structOffset;
            writeLnOffset = structOffset + WRITELN_OFFSET;
            writeLn = reader.readUnsignedShort(writeLnOffset) + structOffset;
            getStatOffset = structOffset + GETSTAT_OFFSET;
            getStat = reader.readUnsignedShort(getStatOffset) + structOffset;
            setStatOffset = structOffset + SETSTAT_OFFSET;
            setStat = reader.readUnsignedShort(setStatOffset) + structOffset;
            closeOffset = structOffset + CLOSE_OFFSET;
            close = reader.readUnsignedShort(closeOffset) + structOffset;
        }

        @Override
        public String getName() {
            return NAME;
        }

        protected void createFunction(Program program, Address moduleAddress, long fieldOffset, long funcOffset, String name)
            throws InvalidInputException, OverlappingFunctionException, CodeUnitInsertionException
        {
            // function
        }

        @Override
        public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException {
            try {
                Helpers.createFunction(program, moduleAddress, createOffset, create, "Create");
                Helpers.createFunction(program, moduleAddress, openOffset, open, "Open");
                Helpers.createFunction(program, moduleAddress, makDirOffset, makDir, "MakDir");
                Helpers.createFunction(program, moduleAddress, chgDirOffset, chgDir, "ChgDir");
                Helpers.createFunction(program, moduleAddress, deleteOffset, delete, "Delete");
                Helpers.createFunction(program, moduleAddress, seekOffset, seek, "Seek");
                Helpers.createFunction(program, moduleAddress, readOffset, read, "Read");
                Helpers.createFunction(program, moduleAddress, writeOffset, write, "Write");
                Helpers.createFunction(program, moduleAddress, readLnOffset, readLn, "ReadLn");
                Helpers.createFunction(program, moduleAddress, writeLnOffset, writeLn, "WriteLn");
                Helpers.createFunction(program, moduleAddress, getStatOffset, getStat, "GetStat");
                Helpers.createFunction(program, moduleAddress, setStatOffset, setStat, "SetStat");
                Helpers.createFunction(program, moduleAddress, closeOffset, close, "Close");
            }
            catch(InvalidInputException | OverlappingFunctionException | CodeUnitInsertionException e) {
                Msg.showError(this, null, "EntryTable", "Failed to create entry table function");
                e.printStackTrace();
            }
        }

        @Override
        public DataType toDataType() throws DuplicateNameException, IOException {
            return staticDataType();
        }

        public static DataType staticDataType() {
            StructureDataType struct = new StructureDataType(new CategoryPath("/OS-9"), NAME, 0);

            struct.add(new UnsignedShortDataType(), "Create", null);
            struct.add(new UnsignedShortDataType(), "Open", null);
            struct.add(new UnsignedShortDataType(), "MakDir", null);
            struct.add(new UnsignedShortDataType(), "ChgDir", null);
            struct.add(new UnsignedShortDataType(), "Delete", null);
            struct.add(new UnsignedShortDataType(), "seek", null);
            struct.add(new UnsignedShortDataType(), "Read", null);
            struct.add(new UnsignedShortDataType(), "Write", null);
            struct.add(new UnsignedShortDataType(), "ReadLn", null);
            struct.add(new UnsignedShortDataType(), "WriteLn", null);
            struct.add(new UnsignedShortDataType(), "GetStat", null);
            struct.add(new UnsignedShortDataType(), "SetStat", null);
            struct.add(new UnsignedShortDataType(), "Close ", null);

            return struct;
        }
    }
}
