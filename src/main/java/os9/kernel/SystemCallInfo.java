/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package os9.kernel;

/**
 * System call information.
 * @author User
 */
public class SystemCallInfo {
    public final String name;
    // public 

    public SystemCallInfo(String syscallName) {
        name = syscallName;
    }
}
