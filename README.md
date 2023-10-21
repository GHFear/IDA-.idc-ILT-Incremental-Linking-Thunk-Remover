# IDA-.idc-ILT-Incremental-Linking-Thunk-Remover
IDA .idc script that patches Incremental Linking Thunks.<br>
C/C++ code with incremental linking enabled links together the functions with thunks of **jmp** instructions to the functions.
This is to make it so you only need to build code that you have made changes to instead of rebuilding all your source code for the project each time you compile the source.
These thunks really only add a single extra **jmp** for each function call, so the performance hit isn't massive, <br>but any performance gain is welcome, so I made this script to patch out instructions we don't really need on release builds.
