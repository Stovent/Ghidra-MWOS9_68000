/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */

package os9.util;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;

/**
 * Interface for all data structure that needs to populate the program.
 * @author Stovent
 */
public interface Structure extends StructConverter {
    /** Returns the name of the extra header. */
    public String getName();

    /** Lets the extra header modify the program to add labels and data types in the program. */
    public void applyToProgram(Address moduleAddress, Program program) throws CodeUnitInsertionException;
}
