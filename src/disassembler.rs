use iced_x86::{Decoder, DecoderOptions, Formatter, GasFormatter};

const COLUMN_BYTE_LENGTH: usize = 10;
const CODE_BITNESS: u32 = 64;

/*
This method produces output like this:
00007FFAC46ACDA4 48895C2410           mov       [rsp+10h],rbx
00007FFAC46ACDA9 4889742418           mov       [rsp+18h],rsi
00007FFAC46ACDAE 55                   push      rbp
00007FFAC46ACDAF 57                   push      rdi
00007FFAC46ACDB0 4156                 push      r14
00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]
00007FFAC46ACDBA 4881EC00020000       sub       rsp,200h
00007FFAC46ACDC1 488B0518570A00       mov       rax,[rel 7FFA`C475`24E0h]
00007FFAC46ACDC8 4833C4               xor       rax,rsp
00007FFAC46ACDCB 488985F0000000       mov       [rbp+0F0h],rax
00007FFAC46ACDD2 4C8B052F240A00       mov       r8,[rel 7FFA`C474`F208h]
00007FFAC46ACDD9 488D05787C0400       lea       rax,[rel 7FFA`C46F`4A58h]
00007FFAC46ACDE0 33FF                 xor       edi,edi
*/
pub(crate) fn print_disassemble(bytes: &[u8], address: u64, max_instructions: usize) {
    let mut decoder = Decoder::with_ip(CODE_BITNESS, bytes, address, DecoderOptions::NONE);
    // Formatters: Masm*, Nasm*, Gas* (AT&T) and Intel* (XED).
    let mut formatter = GasFormatter::new();
    // Change some options, there are many more
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);
    let mut output = String::new();
    for instruction in &mut decoder.iter().take(max_instructions) {
        // Format the instruction ("disassemble" it)
        output.clear();
        formatter.format(&instruction, &mut output);
        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - address) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < COLUMN_BYTE_LENGTH {
            for _ in 0..COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }

        println!(" {}", output);
    }
}
