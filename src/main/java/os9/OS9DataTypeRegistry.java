/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9;

import java.util.Arrays;
import java.util.List;

import ghidra.program.model.data.DataType;

import os9.kernel.*;
import os9.module.*;

/**
 *
 * @author User
 */
public class OS9DataTypeRegistry {
    public static final List<DataType> DATA_TYPES = Arrays.asList(
        //SystemGlobals.staticDataType(),
        //DataHeader.staticDataType(),
        // DeviceDescriptorHeader.staticDataType(),
        // DeviceDriverHeader.staticDataType(),
        //FileManagerHeader.staticDataType(),
        //InitHeader.staticDataType(),
        // ModuleHeader.staticDataType(),
        //ProgramHeader.staticDataType(),
        //SystemHeader.staticDataType(),
        //TrapHandlerHeader.staticDataType()
    );
}
