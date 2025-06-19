/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.util;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

/**
 *
 * @author Stovent
 */
public class Helpers {
    /**
     * Creates a reference from fieldOffset to dataOffset in the program.
     * If fieldOffset or dataOffset is zero, nothing is created.
     * @param program The program
     * @param moduleAddress The address of the start of header
     * @param fieldOffset The offset from the header base to the field that references
     * @param dataOffset The offset from the header base to the referenced
     */
    public static void createReference(Program program, Address moduleAddress, long fieldOffset, long dataOffset) throws CodeUnitInsertionException {
        if(fieldOffset > 0 && dataOffset > 0) {
            Address fieldAddress = moduleAddress.add(fieldOffset);
            Address dataAddress = moduleAddress.add(dataOffset);
            ReferenceManager refManager = program.getReferenceManager();
            refManager.addMemoryReference(fieldAddress, dataAddress, RefType.DATA, SourceType.ANALYSIS, 0);
        }
    }

    /**
     * Creates a data at dataOffset in the program.
     * If dataOffset is zero, nothing is created.
     * If fieldOffset is non-zero, a memory reference is created from fieldOffset to dataOffset.
     * @param program The program
     * @param moduleAddress The address of the start of header
     * @param fieldOffset The offset from the header base to the field that references the data
     * @param dataOffset The offset from the header base to the referenced data
     * @param dataType The type of data to create
     */
    public static void createData(Program program, Address moduleAddress, long fieldOffset, long dataOffset, DataType dataType) throws CodeUnitInsertionException {
        if(dataOffset > 0) {
            Address dataAddress = moduleAddress.add(dataOffset);
            DataUtilities.createData(program, dataAddress, dataType, -1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

            if(fieldOffset > 0) {
                Address fieldAddress = moduleAddress.add(fieldOffset);
                ReferenceManager refManager = program.getReferenceManager();
                refManager.addMemoryReference(fieldAddress, dataAddress, RefType.DATA, SourceType.ANALYSIS, 0);
            }
        }
    }

    /**
     * Creates a null-terminated string at dataOffset in the program.
     * If fieldOffset or dataOffset is zero, nothing is created.
     * @param program The program
     * @param moduleAddress The address of the start of header
     * @param fieldOffset The offset from the header base to the field that references the string
     * @param dataOffset The offset from the header base to the string
     */
    public static void createString(Program program, Address moduleAddress, long fieldOffset, long dataOffset) throws CodeUnitInsertionException {
        createData(program, moduleAddress, fieldOffset, dataOffset, new TerminatedStringDataType());
    }

    /**
     * Creates a function at the given funcOffset in the program.
     * If fieldOffset or funcOffset is zero, nothing is created.
     * @param program The program
     * @param moduleAddress The address of the start of header
     * @param fieldOffset The offset from the header base to the field that references the function
     * @param funcOffset The offset from the header base to the function code
     * @param name The name of the function
     */
    public static Function createFunction(Program program, Address moduleAddress, long fieldOffset, long funcOffset, String name)
        throws InvalidInputException, OverlappingFunctionException, CodeUnitInsertionException
    {
        if(fieldOffset > 0 && funcOffset > 0) {
            Address funcAddress = moduleAddress.add(funcOffset);
            FunctionManager functionManager = program.getFunctionManager();
            Function function = functionManager.getFunctionAt(funcAddress);

            if(function == null) { // There are cases where functions are the same (like nvdrv GetStat/SetStat)
                function = functionManager.createFunction(name, funcAddress, new AddressSet(funcAddress), SourceType.ANALYSIS);
            } else {
                function = null; // if function already exists, return null to not modify the already there function.
            }

            createReference(program, moduleAddress, fieldOffset, funcOffset);

            return function;
        }

        return null;
    }

    public static void createIDataBlock(Program program) {
    }
}
