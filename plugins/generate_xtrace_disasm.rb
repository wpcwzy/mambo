#!/usr/bin/env ruby

def parse_inst_file(filename, prefix)
  insts = []
  seen = {}
  File.foreach(filename) do |line|
    line = line.strip
    next if line.empty? || line.start_with?('#')

    token = line.split(/[,\s]+/).first
    next if token.nil? || token.empty?

    enum_name = prefix + token.upcase
    next if seen[enum_name]

    seen[enum_name] = true
    insts << [enum_name, token.downcase]
  end
  insts
end

def emit_table(fn_name, type_name, insts)
  puts "static inline const char *#{fn_name}(#{type_name} inst) {"
  puts "  switch (inst) {"
  insts.each do |enum_name, text|
    puts "    case #{enum_name}: return \"#{text}\";"
  end
  puts "    default: return \"unknown\";"
  puts "  }"
  puts "}"
  puts
end

riscv = parse_inst_file(File.expand_path("../pie/riscv.txt", __dir__), "RISCV_")
# RVC encoding names such as c_sdsp are not assembly mnemonics. Emit the
# equivalent base instruction name so trace consumers see one RV64 vocabulary.
riscv_base_names = {
  "c_addi4spn" => "addi",
  "c_fldsp" => "fld",
  "c_lwsp" => "lw",
  "c_flwsp" => "flw",
  "c_ldsp" => "ld",
  "c_fsdsp" => "fsd",
  "c_swsp" => "sw",
  "c_sdsp" => "sd",
  "c_addi16sp" => "addi"
}
riscv.each do |inst|
  token = inst[1]
  token = riscv_base_names.fetch(token, token.delete_prefix("c_"))
  token = "fence.i" if token == "fencei"
  token = token.tr("_", ".") unless token.start_with?("v_")
  inst[1] = token
end
a64 = parse_inst_file(File.expand_path("../pie/a64.txt", __dir__), "A64_")
arm = parse_inst_file(File.expand_path("../pie/arm.txt", __dir__), "ARM_")
thumb = parse_inst_file(File.expand_path("../pie/thumb.txt", __dir__), "THUMB_")

puts "#ifndef XTRACE_DISASM_H"
puts "#define XTRACE_DISASM_H"
puts
puts "#include \"../plugins.h\""
puts
puts "#if defined(__riscv)"
emit_table("xtrace_riscv_name", "riscv_instruction", riscv)
puts "#endif"
puts
puts "#if defined(__aarch64__)"
emit_table("xtrace_a64_name", "a64_instruction", a64)
puts "#endif"
puts
puts "#if defined(__arm__)"
emit_table("xtrace_arm_name", "arm_instruction", arm)
emit_table("xtrace_thumb_name", "thumb_instruction", thumb)
puts "#endif"

puts "static inline const char *xtrace_inst_name(int inst_type, int inst) {"
puts "#if defined(__riscv)"
puts "  return xtrace_riscv_name((riscv_instruction)inst);"
puts "#elif defined(__aarch64__)"
puts "  return xtrace_a64_name((a64_instruction)inst);"
puts "#elif defined(__arm__)"
puts "  if (inst_type == THUMB_INST) {"
puts "    return xtrace_thumb_name((thumb_instruction)inst);"
puts "  }"
puts "  return xtrace_arm_name((arm_instruction)inst);"
puts "#else"
puts "  return \"unknown\";"
puts "#endif"
puts "}"
puts
puts "#endif"
