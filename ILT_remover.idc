//IDA ILT (Incremental Linking Thunks) Remover - Version 0.2
#include <idc.idc>
#ifdef __EA64__
#define TO_LONG(x) (inf_is_64bit() ? (x) : (((x) << 32) >> 32))
#else
#define TO_LONG(x) (x)
#endif

static uint32_to_int32(value)
{
    return (value ^ (1 << 31)) - (1 << 31);
}

static make_rel_addr(og_func, xref)
{   
    return og_func - xref;
}


static patch_stuff(ea, value, wordsize)
{    
    if (wordsize == 1)
        patch_byte(ea, value);
    else if (wordsize == 2)
        patch_word(ea, value);
    else if (wordsize == 4)
        patch_dword(ea, value);
    else if (wordsize == 8)
        patch_qword(ea, value);
    else {
        print("Invalid wordsize");
        }
}


static get_instruction_type(addr)
{
    auto byte1, byte2, byte3, byte4;
    byte1 = get_wide_byte(addr);
    if ( byte1 == 0x48) //64bit op
    {
        byte2 = get_wide_byte(addr+0x1);
        if ( byte2 == 0xE8 ) //Call relative address 64bit
        {
            return "CALL64";
        }
        else if ( byte2 == 0x8D ) //lea relative address 64bit
        {
            return "LEA64";
        }
        else //unknown instruction
        { 
            return "UNKNOWN1";
        }
    }
    else if ( byte1 == 0xE9 ) //jmp relative address
    {
        return "JMP";
    }
    else if ( byte1 == 0x8D ) //lea 32bit relative address
    {
        return "LEA32";
    }
    else if ( byte1 == 0xE8 ) //Call relative address 32bit
    {
        return "CALL32";
    }
    else if ( byte1 == 0x0F ) //double opcode instruction?
    {
        byte2 = get_wide_byte(addr+0x1);
        if ( byte2 == 0x84 ) //jz relative address
        {
            return "JZ";
        }
        else if ( byte2 == 0x85 ) //jnz relative address
        {
            return "JNZ";
        }
        else //unknown instruction
        { 
            return "UNKNOWN2";
        }
    }
    else //unknown instruction
    { 
        return "UNKNOWN3";
    }
}

static get_opcode_size(type)
{
    if ( type == "CALL64" )
    {
        return 0x2;
    }
    else if ( type == "LEA64" )
    {
        return 0x2;
    }
    else if ( type == "JMP" )
    {
        return 0x1;
    }
    else if ( type == "LEA32" )
    {
        return 0x1;
    }
    else if ( type == "CALL32" )
    {
        return 0x1;
    }
    else if ( type == "JZ" )
    {
        return 0x2;
    }
    else if ( type == "JNZ" )
    {
        return 0x2;
    }
    else
    {
        return -1;
    }
}




static get_og_function_rel_addr(current_function, xref_to, instruction_type, op_code_size)
{   
    auto op_and_addr = op_code_size + 0x4;
    auto func_rel_addr = get_wide_dword(xref_to + op_code_size);
    auto rel_addr_and_instruction = uint32_to_int32(func_rel_addr) + op_and_addr;
    auto original_function_relative_address = xref_to+rel_addr_and_instruction;
	auto relative_to_xref = 0x0;
	auto xref_and_opcode = 0x0;
	auto relative_addr_minus_instruction = 0x0;
    if ( instruction_type == "CALL32" || instruction_type == "JMP" )
    {
        msg("FIXABLE \n");
        relative_to_xref = make_rel_addr(current_function, xref_to);
        msg("relative to xref: %08lX  \n", relative_to_xref);
        msg(" -- current_function: %lX and res: %lX and xref_to: %lX \n", current_function, relative_to_xref, xref_to);
        xref_and_opcode = xref_to + op_code_size;
        relative_addr_minus_instruction = (relative_to_xref - 0x4) - op_code_size;
        msg("Relative Address Minus Instructions: %X \n", relative_addr_minus_instruction);
        patch_stuff(xref_and_opcode, relative_addr_minus_instruction, 0x4);
        
    }
    else if ( instruction_type == "JZ" || instruction_type == "JNZ" )
    {
        msg("FIXABLE \n");
        relative_to_xref = make_rel_addr(current_function, xref_to);
        msg("relative to xref: %08lX  \n", relative_to_xref);
        msg(" -- current_function: %lX and res: %lX and xref_to: %lX \n", current_function, relative_to_xref, xref_to);
        xref_and_opcode = xref_to + op_code_size;
        relative_addr_minus_instruction = (relative_to_xref - 0x4) - op_code_size;
        msg("Relative Address Minus Instructions: %X \n", relative_addr_minus_instruction);
        msg("Absolute Address Minus Instructions: %X \n", relative_addr_minus_instruction);
        patch_stuff(xref_and_opcode, relative_addr_minus_instruction, 0x4);
        
    }
    else
    {
        msg("NOT FIXABLE \n");
    }
    
    return original_function_relative_address;
}



static get_real_function_addr(mutil_func, jmp_near_instruction_size)
{
    
    auto function_jmp_loc = get_wide_dword(mutil_func + 0x1); //input address + jmp instruction size without the location data (4bytes).
    
    auto function_jmp_loc_int32 = uint32_to_int32(function_jmp_loc);
    
    return (mutil_func + jmp_near_instruction_size + function_jmp_loc_int32); 
    //ILT JMP Function Address + jmp instruction size + function jmp location, 
    //then return it.
}


static ILT_mutil_type(op_code)
{
    if ( op_code == 0xEB ) //Jump short
    {
        return "JMP_SHORT";
    }
    else if ( op_code == 0xE9 ) //Jump near, relative, displacement relative to next instruction. && get_func_name(mutil_func) == "j_IsNonPakFileNameAllowed"
    {
        return "JMP_NEAR_REL";
    }
    else if ( op_code == 0xFF ) //Jump near, absolute indirect
    {
        return "JMP_NEAR_ABS";
    }
    else if ( op_code == 0xEA ) //Jump far, absolute, address given in operand.
    {
        return "JMP_FAR_ABS";
    }
    else //UNKNOWN
    {
        return "UNKNOWN";
    }
}


static is_ILT_mutil(op_code)
{
    
    if ( op_code == 0xEB ) //Jump short
    {
        return 0;
    }
    else if ( op_code == 0xE9 ) //Jump near, relative, displacement relative to next instruction. && get_func_name(mutil_func) == "j_IsNonPakFileNameAllowed"
    {
        return 1;
    }
    else if ( op_code == 0xFF ) //Jump near, absolute indirect
    {
        return 0;
    }
    else if ( op_code == 0xEA ) //Jump far, absolute, address given in operand.
    {
        return 0;
    }
    else //UNKNOWN
    {
        return 0;
    }
}


static main() 
{
  auto ea, func_end, func_flag, func_size;
  
  for ( ea=get_next_func(0); ea != BADADDR; ea=get_next_func(ea))
  {

    func_flag = get_func_flags(ea);
    func_end = find_func_end(ea);
    func_size = (func_end - ea);
    auto first_op_code = get_wide_byte(ea);
    
    if ( func_size != 0x5 ){continue;}
    if ( is_ILT_mutil(first_op_code) == 0 ){continue;}
    
    Message("ILT %s at: %08lX \n -- Name: %s \n", ILT_mutil_type(first_op_code), ea, get_func_name(ea));
    Message("Original Function at: %08lX \n -- Name: %s \n", get_real_function_addr(ea, 0x5), get_func_name(get_real_function_addr(ea, 0x5))); 
    
    auto real_func = get_real_function_addr(ea, 0x5);
    
    Message(" -- Function Ends: %08lX \n", func_end);
    
    auto xref_from, xref_to, xref_from_addr, xref_to_addr, xref_type, xref_current;

    for (xref_to=get_first_cref_to(ea); xref_to != BADADDR; xref_to=get_next_cref_to(ea, xref_to))
    {
        auto instruction_type = get_instruction_type(xref_to);
        
        auto op_code_size = get_opcode_size(instruction_type);
        
        msg(" -- XREF Instruction Is a %s \n", instruction_type);
        
        auto xref_instruction_address = get_og_function_rel_addr(real_func, xref_to, instruction_type, op_code_size);
        
        msg(" -- XREF Instruction Address: %08lX \n", xref_instruction_address);
        
    }
    
    
    if ( func_flag & FUNC_NORET )
    {
      Message(" NORET");
    }
    if ( func_flag & FUNC_FAR )
    {
      Message(" FAR");
    }
    
    Message("\n");
  }
  
}
