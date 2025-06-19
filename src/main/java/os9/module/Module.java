/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.module;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import os9.util.InvalidModuleHeaderException;

/**
 *
 * @author Stovent
 */
public class Module {
    public static final String NAME = "OS-9 Header";

    private ModuleHeader header;

    public Module(ByteProvider provider) throws InvalidModuleHeaderException, IOException {
        header = new ModuleHeader(provider);
    }

    public final ModuleHeader getHeader() {
        return header;
    }

    /** Applies all the module data structures to the given program. */
    public void applyToProgram(Program program) throws CodeUnitInsertionException {
        header.applyToProgram(program.getImageBase(), program);
    }
}
