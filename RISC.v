// Code your design here

//  RISC-V + AES Single Cycle Processor
//  WITH AES-128 Key Expansion Block




//  TOP MODULE


module RISC(
    input clk,
    input reset
);


// PC

wire [31:0] pc;
wire [31:0] next_pc;

pc PC(
    .clk(clk),
    .reset(reset),
    .next_pc(next_pc),
    .pc(pc)
);


// Instruction Memory

wire [31:0] instruction;

instr_cache IM(
    .pc(pc),
    .instruction(instruction)
);


// Decoder

wire [6:0] opcode;
wire [4:0] rd;
wire [4:0] rs1;
wire [4:0] rs2;
wire [2:0] funct3;
wire [6:0] funct7;

decoder DEC(
    .instruction(instruction),
    .opcode(opcode),
    .rd(rd),
    .rs1(rs1),
    .rs2(rs2),
    .funct3(funct3),
    .funct7(funct7)
);


// Control Unit

wire RegWrite;
wire MemRead;
wire MemWrite;
wire ALUSrc;
wire Branch;
wire Jump;
wire LUI;
wire AES_EN;

control_unit CU(
    .opcode(opcode),
    .RegWrite(RegWrite),
    .MemRead(MemRead),
    .MemWrite(MemWrite),
    .ALUSrc(ALUSrc),
    .Branch(Branch),
    .Jump(Jump),
    .LUI(LUI),
    .AES_EN(AES_EN)
);


// Register File

wire [31:0] reg_data1;
wire [31:0] reg_data2;
wire [31:0] write_data;

reg_file RF(
    .clk(clk),
    .RegWrite(RegWrite),
    .rs1(rs1),
    .rs2(rs2),
    .rd(rd),
    .write_data(write_data),
    .read_data1(reg_data1),
    .read_data2(reg_data2)
);


// Immediate Generator

wire [31:0] imm;

imm_gen IMM(
    .instruction(instruction),
    .imm(imm)
);


// ALU Input MUX

wire [31:0] alu_in2;

mux_alu_src ALU_MUX(
    .reg_data(reg_data2),
    .imm(imm),
    .ALUSrc(ALUSrc),
    .alu_in(alu_in2)
);


// ALU Control

wire [1:0] func_class;
wire [1:0] shift_op;
wire add_sub;
wire [1:0] logic_fn;

wire is_rtype = (opcode == 7'b0110011);

alu_control ALUCTRL(
    .funct3(funct3),
    .funct7(funct7),
    .is_rtype(is_rtype),
    .func_class(func_class),
    .shift_op(shift_op),
    .add_sub(add_sub),
    .logic_fn(logic_fn)
);


// ALU

wire [31:0] alu_out;

ALU ALU1(
    .x(reg_data1),
    .y(alu_in2),
    .func_class(func_class),
    .shift_op(shift_op),
    .add_sub(add_sub),
    .logic_fn(logic_fn),
    .s(alu_out)
);


// Data Memory

wire [31:0] mem_out;

data_cache DM(
    .clk(clk),
    .mem_read(MemRead),
    .mem_write(MemWrite),
    .addr(alu_out),
    .write_data(reg_data2),
    .read_data(mem_out)
);


// AES Block


wire [127:0] aes_data;
wire [127:0] aes_key;
wire [127:0] aes_out;
wire [31:0]  aes_result;

assign aes_data = {reg_data1, reg_data2, reg_data1, reg_data2};
assign aes_key  = {reg_data1, reg_data2, reg_data1, reg_data2};

AES AES_CORE(
    .data(aes_data),
    .key(aes_key),
    .aes_op(funct3),
    .out(aes_out)
);

assign aes_result = aes_out[31:0];


// Writeback MUX

mux_writeback WB(
    .alu_out(alu_out),
    .mem_out(mem_out),
    .aes_out(aes_result),
    .pc_plus4(pc + 32'd4),
    .MemRead(MemRead),
    .Jump(Jump),
    .AES_EN(AES_EN),
    .write_data(write_data)
);


// Branch Checker

wire BrTrue;

branch_checker BC(
    .rs(reg_data1),
    .rt(reg_data2),
    .funct3(funct3),
    .BrTrue(BrTrue)
);


// Next PC

next_addr NA(
    .pc(pc),
    .imm(imm),
    .PCSrc({Jump, Branch}),
    .BrTrue(BrTrue),
    .next_pc(next_pc)
);

endmodule



//  AES TOP  


module AES(
    input  [127:0] data,
    input  [127:0] key,
    input  [2:0]   aes_op,
    output reg [127:0] out
);

wire [127:0] sub_out;
wire [127:0] shift_out;
wire [127:0] mix_out;
wire [127:0] enc_out;
wire [1407:0] round_keys;

aes_subbytes   u1(data, sub_out);
aes_shiftrows  u2(data, shift_out);
aes_mixcolumns u3(data, mix_out);

aes_key_expand keyexp(key, round_keys);

aes_encrypt u4(data, round_keys, enc_out);

always @(*) begin
    case(aes_op)
        3'b001: out = sub_out;       // aessub
        3'b010: out = shift_out;     // aesshift
        3'b011: out = mix_out;       // aesmix
        3'b100: out = data ^ key;    // aeskey
        3'b101: out = enc_out;       // aesenc
        default: out = 128'b0;
    endcase
end

endmodule



//  AES ENCRYPT  


module aes_encrypt(
    input  [127:0]  data,
    input  [1407:0] round_keys,
    output [127:0]  out
);

wire [127:0] r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10;

assign r0 = data ^ round_keys[1407:1280];

aes_round round1(r0, round_keys[1279:1152], r1);
aes_round round2(r1, round_keys[1151:1024], r2);
aes_round round3(r2, round_keys[1023:896],  r3);
aes_round round4(r3, round_keys[895:768],   r4);
aes_round round5(r4, round_keys[767:640],   r5);
aes_round round6(r5, round_keys[639:512],   r6);
aes_round round7(r6, round_keys[511:384],   r7);
aes_round round8(r7, round_keys[383:256],   r8);
aes_round round9(r8, round_keys[255:128],   r9);

aes_final round10(r9, round_keys[127:0],    r10);

assign out = r10;

endmodule



//  AES ROUND  


module aes_round(
    input  [127:0] data,
    input  [127:0] key,
    output [127:0] out
);

wire [127:0] sub;
wire [127:0] shift;
wire [127:0] mix;

aes_subbytes   sb(data,  sub);
aes_shiftrows  sr(sub,   shift);
aes_mixcolumns mc(shift, mix);

assign out = mix ^ key;

endmodule



//  AES FINAL ROUND 


module aes_final(
    input  [127:0] data,
    input  [127:0] key,
    output [127:0] out
);

wire [127:0] sub;
wire [127:0] shift;

aes_subbytes  sb(data, sub);
aes_shiftrows sr(sub,  shift);

assign out = shift ^ key;

endmodule



//  AES SUBBYTES 


module aes_subbytes(
    input  [127:0] in,
    output [127:0] out
);

genvar i;
generate
    for(i = 0; i < 16; i = i+1) begin : sbox
        aes_sbox s(
            .a(in[8*i +: 8]),
            .d(out[8*i +: 8])
        );
    end
endgenerate

endmodule



//  AES SUBWORD 


module aes_subword(
    input  [31:0] in,
    output [31:0] out
);

aes_sbox s0(.a(in[31:24]), .d(out[31:24]));
aes_sbox s1(.a(in[23:16]), .d(out[23:16]));
aes_sbox s2(.a(in[15:8]),  .d(out[15:8]));
aes_sbox s3(.a(in[7:0]),   .d(out[7:0]));

endmodule



//  AES SHIFTROWS  


module aes_shiftrows(
    input  [127:0] in,
    output [127:0] out
);

assign out = {
    in[127:120], in[87:80],   in[47:40],   in[7:0],
    in[95:88],   in[55:48],   in[15:8],    in[103:96],
    in[63:56],   in[23:16],   in[111:104], in[71:64],
    in[31:24],   in[119:112], in[79:72],   in[39:32]
};

endmodule



//  AES MIXCOLUMNS  


module aes_mixcolumns(
    input  [127:0] in,
    output [127:0] out
);

function [7:0] xtime;
    input [7:0] b;
    begin
        xtime = (b << 1) ^ (b[7] ? 8'h1b : 8'h00);
    end
endfunction

function [7:0] mul3;
    input [7:0] b;
    begin
        mul3 = xtime(b) ^ b;
    end
endfunction

function [31:0] mixcol;
    input [31:0] c;
    reg [7:0] a0, a1, a2, a3;
    begin
        
        a0 = c[31:24];
        a1 = c[23:16];
        a2 = c[15:8];
        a3 = c[7:0];

        mixcol[31:24] = xtime(a0) ^ mul3(a1) ^ a2        ^ a3;
        mixcol[23:16] = a0        ^ xtime(a1) ^ mul3(a2)  ^ a3;
        mixcol[15:8]  = a0        ^ a1        ^ xtime(a2) ^ mul3(a3);
        mixcol[7:0]   = mul3(a0)  ^ a1        ^ a2        ^ xtime(a3);
    end
endfunction

assign out = {
    mixcol(in[127:96]),
    mixcol(in[95:64]),
    mixcol(in[63:32]),
    mixcol(in[31:0])
};

endmodule



//  AES KEY EXPANSION  


module aes_key_expand(
    input  [127:0]  key,
    output [1407:0] round_keys
);

wire [31:0] W [0:43];

assign W[0] = key[127:96];
assign W[1] = key[95:64];
assign W[2] = key[63:32];
assign W[3] = key[31:0];

wire [31:0] temp1,  temp2,  temp3,  temp4,  temp5;
wire [31:0] temp6,  temp7,  temp8,  temp9,  temp10;

aes_subword sw1  ({W[3][23:0],  W[3][31:24]},  temp1);
aes_subword sw2  ({W[7][23:0],  W[7][31:24]},  temp2);
aes_subword sw3  ({W[11][23:0], W[11][31:24]}, temp3);
aes_subword sw4  ({W[15][23:0], W[15][31:24]}, temp4);
aes_subword sw5  ({W[19][23:0], W[19][31:24]}, temp5);
aes_subword sw6  ({W[23][23:0], W[23][31:24]}, temp6);
aes_subword sw7  ({W[27][23:0], W[27][31:24]}, temp7);
aes_subword sw8  ({W[31][23:0], W[31][31:24]}, temp8);
aes_subword sw9  ({W[35][23:0], W[35][31:24]}, temp9);
aes_subword sw10 ({W[39][23:0], W[39][31:24]}, temp10);

assign W[4]  = W[0] ^ temp1  ^ 32'h01000000;
assign W[5]  = W[1] ^ W[4];
assign W[6]  = W[2] ^ W[5];
assign W[7]  = W[3] ^ W[6];

assign W[8]  = W[4] ^ temp2  ^ 32'h02000000;
assign W[9]  = W[5] ^ W[8];
assign W[10] = W[6] ^ W[9];
assign W[11] = W[7] ^ W[10];

assign W[12] = W[8]  ^ temp3  ^ 32'h04000000;
assign W[13] = W[9]  ^ W[12];
assign W[14] = W[10] ^ W[13];
assign W[15] = W[11] ^ W[14];

assign W[16] = W[12] ^ temp4  ^ 32'h08000000;
assign W[17] = W[13] ^ W[16];
assign W[18] = W[14] ^ W[17];
assign W[19] = W[15] ^ W[18];

assign W[20] = W[16] ^ temp5  ^ 32'h10000000;
assign W[21] = W[17] ^ W[20];
assign W[22] = W[18] ^ W[21];
assign W[23] = W[19] ^ W[22];

assign W[24] = W[20] ^ temp6  ^ 32'h20000000;
assign W[25] = W[21] ^ W[24];
assign W[26] = W[22] ^ W[25];
assign W[27] = W[23] ^ W[26];

assign W[28] = W[24] ^ temp7  ^ 32'h40000000;
assign W[29] = W[25] ^ W[28];
assign W[30] = W[26] ^ W[29];
assign W[31] = W[27] ^ W[30];

assign W[32] = W[28] ^ temp8  ^ 32'h80000000;
assign W[33] = W[29] ^ W[32];
assign W[34] = W[30] ^ W[33];
assign W[35] = W[31] ^ W[34];

assign W[36] = W[32] ^ temp9  ^ 32'h1b000000;
assign W[37] = W[33] ^ W[36];
assign W[38] = W[34] ^ W[37];
assign W[39] = W[35] ^ W[38];

assign W[40] = W[36] ^ temp10 ^ 32'h36000000;
assign W[41] = W[37] ^ W[40];
assign W[42] = W[38] ^ W[41];
assign W[43] = W[39] ^ W[42];

assign round_keys = {
    {W[0],  W[1],  W[2],  W[3]},
    {W[4],  W[5],  W[6],  W[7]},
    {W[8],  W[9],  W[10], W[11]},
    {W[12], W[13], W[14], W[15]},
    {W[16], W[17], W[18], W[19]},
    {W[20], W[21], W[22], W[23]},
    {W[24], W[25], W[26], W[27]},
    {W[28], W[29], W[30], W[31]},
    {W[32], W[33], W[34], W[35]},
    {W[36], W[37], W[38], W[39]},
    {W[40], W[41], W[42], W[43]}
};

endmodule



//  AES SBOX — Full 256-entry lookup table


module aes_sbox(
    input  [7:0] a,
    output reg [7:0] d
);

always @(*) begin
    case(a)
        8'h00:d=8'h63; 8'h01:d=8'h7c; 8'h02:d=8'h77; 8'h03:d=8'h7b;
        8'h04:d=8'hf2; 8'h05:d=8'h6b; 8'h06:d=8'h6f; 8'h07:d=8'hc5;
        8'h08:d=8'h30; 8'h09:d=8'h01; 8'h0a:d=8'h67; 8'h0b:d=8'h2b;
        8'h0c:d=8'hfe; 8'h0d:d=8'hd7; 8'h0e:d=8'hab; 8'h0f:d=8'h76;
        8'h10:d=8'hca; 8'h11:d=8'h82; 8'h12:d=8'hc9; 8'h13:d=8'h7d;
        8'h14:d=8'hfa; 8'h15:d=8'h59; 8'h16:d=8'h47; 8'h17:d=8'hf0;
        8'h18:d=8'had; 8'h19:d=8'hd4; 8'h1a:d=8'ha2; 8'h1b:d=8'haf;
        8'h1c:d=8'h9c; 8'h1d:d=8'ha4; 8'h1e:d=8'h72; 8'h1f:d=8'hc0;
        8'h20:d=8'hb7; 8'h21:d=8'hfd; 8'h22:d=8'h93; 8'h23:d=8'h26;
        8'h24:d=8'h36; 8'h25:d=8'h3f; 8'h26:d=8'hf7; 8'h27:d=8'hcc;
        8'h28:d=8'h34; 8'h29:d=8'ha5; 8'h2a:d=8'he5; 8'h2b:d=8'hf1;
        8'h2c:d=8'h71; 8'h2d:d=8'hd8; 8'h2e:d=8'h31; 8'h2f:d=8'h15;
        8'h30:d=8'h04; 8'h31:d=8'hc7; 8'h32:d=8'h23; 8'h33:d=8'hc3;
        8'h34:d=8'h18; 8'h35:d=8'h96; 8'h36:d=8'h05; 8'h37:d=8'h9a;
        8'h38:d=8'h07; 8'h39:d=8'h12; 8'h3a:d=8'h80; 8'h3b:d=8'he2;
        8'h3c:d=8'heb; 8'h3d:d=8'h27; 8'h3e:d=8'hb2; 8'h3f:d=8'h75;
        8'h40:d=8'h09; 8'h41:d=8'h83; 8'h42:d=8'h2c; 8'h43:d=8'h1a;
        8'h44:d=8'h1b; 8'h45:d=8'h6e; 8'h46:d=8'h5a; 8'h47:d=8'ha0;
        8'h48:d=8'h52; 8'h49:d=8'h3b; 8'h4a:d=8'hd6; 8'h4b:d=8'hb3;
        8'h4c:d=8'h29; 8'h4d:d=8'he3; 8'h4e:d=8'h2f; 8'h4f:d=8'h84;
        8'h50:d=8'h53; 8'h51:d=8'hd1; 8'h52:d=8'h00; 8'h53:d=8'hed;
        8'h54:d=8'h20; 8'h55:d=8'hfc; 8'h56:d=8'hb1; 8'h57:d=8'h5b;
        8'h58:d=8'h6a; 8'h59:d=8'hcb; 8'h5a:d=8'hbe; 8'h5b:d=8'h39;
        8'h5c:d=8'h4a; 8'h5d:d=8'h4c; 8'h5e:d=8'h58; 8'h5f:d=8'hcf;
        8'h60:d=8'hd0; 8'h61:d=8'hef; 8'h62:d=8'haa; 8'h63:d=8'hfb;
        8'h64:d=8'h43; 8'h65:d=8'h4d; 8'h66:d=8'h33; 8'h67:d=8'h85;
        8'h68:d=8'h45; 8'h69:d=8'hf9; 8'h6a:d=8'h02; 8'h6b:d=8'h7f;
        8'h6c:d=8'h50; 8'h6d:d=8'h3c; 8'h6e:d=8'h9f; 8'h6f:d=8'ha8;
        8'h70:d=8'h51; 8'h71:d=8'ha3; 8'h72:d=8'h40; 8'h73:d=8'h8f;
        8'h74:d=8'h92; 8'h75:d=8'h9d; 8'h76:d=8'h38; 8'h77:d=8'hf5;
        8'h78:d=8'hbc; 8'h79:d=8'hb6; 8'h7a:d=8'hda; 8'h7b:d=8'h21;
        8'h7c:d=8'h10; 8'h7d:d=8'hff; 8'h7e:d=8'hf3; 8'h7f:d=8'hd2;
        8'h80:d=8'hcd; 8'h81:d=8'h0c; 8'h82:d=8'h13; 8'h83:d=8'hec;
        8'h84:d=8'h5f; 8'h85:d=8'h97; 8'h86:d=8'h44; 8'h87:d=8'h17;
        8'h88:d=8'hc4; 8'h89:d=8'ha7; 8'h8a:d=8'h7e; 8'h8b:d=8'h3d;
        8'h8c:d=8'h64; 8'h8d:d=8'h5d; 8'h8e:d=8'h19; 8'h8f:d=8'h73;
        8'h90:d=8'h60; 8'h91:d=8'h81; 8'h92:d=8'h4f; 8'h93:d=8'hdc;
        8'h94:d=8'h22; 8'h95:d=8'h2a; 8'h96:d=8'h90; 8'h97:d=8'h88;
        8'h98:d=8'h46; 8'h99:d=8'hee; 8'h9a:d=8'hb8; 8'h9b:d=8'h14;
        8'h9c:d=8'hde; 8'h9d:d=8'h5e; 8'h9e:d=8'h0b; 8'h9f:d=8'hdb;
        8'ha0:d=8'he0; 8'ha1:d=8'h32; 8'ha2:d=8'h3a; 8'ha3:d=8'h0a;
        8'ha4:d=8'h49; 8'ha5:d=8'h06; 8'ha6:d=8'h24; 8'ha7:d=8'h5c;
        8'ha8:d=8'hc2; 8'ha9:d=8'hd3; 8'haa:d=8'hac; 8'hab:d=8'h62;
        8'hac:d=8'h91; 8'had:d=8'h95; 8'hae:d=8'he4; 8'haf:d=8'h79;
        8'hb0:d=8'he7; 8'hb1:d=8'hc8; 8'hb2:d=8'h37; 8'hb3:d=8'h6d;
        8'hb4:d=8'h8d; 8'hb5:d=8'hd5; 8'hb6:d=8'h4e; 8'hb7:d=8'ha9;
        8'hb8:d=8'h6c; 8'hb9:d=8'h56; 8'hba:d=8'hf4; 8'hbb:d=8'hea;
        8'hbc:d=8'h65; 8'hbd:d=8'h7a; 8'hbe:d=8'hae; 8'hbf:d=8'h08;
        8'hc0:d=8'hba; 8'hc1:d=8'h78; 8'hc2:d=8'h25; 8'hc3:d=8'h2e;
        8'hc4:d=8'h1c; 8'hc5:d=8'ha6; 8'hc6:d=8'hb4; 8'hc7:d=8'hc6;
        8'hc8:d=8'he8; 8'hc9:d=8'hdd; 8'hca:d=8'h74; 8'hcb:d=8'h1f;
        8'hcc:d=8'h4b; 8'hcd:d=8'hbd; 8'hce:d=8'h8b; 8'hcf:d=8'h8a;
        8'hd0:d=8'h70; 8'hd1:d=8'h3e; 8'hd2:d=8'hb5; 8'hd3:d=8'h66;
        8'hd4:d=8'h48; 8'hd5:d=8'h03; 8'hd6:d=8'hf6; 8'hd7:d=8'h0e;
        8'hd8:d=8'h61; 8'hd9:d=8'h35; 8'hda:d=8'h57; 8'hdb:d=8'hb9;
        8'hdc:d=8'h86; 8'hdd:d=8'hc1; 8'hde:d=8'h1d; 8'hdf:d=8'h9e;
        8'he0:d=8'he1; 8'he1:d=8'hf8; 8'he2:d=8'h98; 8'he3:d=8'h11;
        8'he4:d=8'h69; 8'he5:d=8'hd9; 8'he6:d=8'h8e; 8'he7:d=8'h94;
        8'he8:d=8'h9b; 8'he9:d=8'h1e; 8'hea:d=8'h87; 8'heb:d=8'he9;
        8'hec:d=8'hce; 8'hed:d=8'h55; 8'hee:d=8'h28; 8'hef:d=8'hdf;
        8'hf0:d=8'h8c; 8'hf1:d=8'ha1; 8'hf2:d=8'h89; 8'hf3:d=8'h0d;
        8'hf4:d=8'hbf; 8'hf5:d=8'he6; 8'hf6:d=8'h42; 8'hf7:d=8'h68;
        8'hf8:d=8'h41; 8'hf9:d=8'h99; 8'hfa:d=8'h2d; 8'hfb:d=8'h0f;
        8'hfc:d=8'hb0; 8'hfd:d=8'h54; 8'hfe:d=8'hbb; 8'hff:d=8'h16;
        default: d = 8'h00;
    endcase
end

endmodule



//  PC REGISTER


module pc(
    input         clk,
    input         reset,
    input  [31:0] next_pc,
    output reg [31:0] pc
);

always @(posedge clk or posedge reset) begin
    if(reset) pc <= 32'b0;
    else      pc <= next_pc;
end

endmodule



//  INSTRUCTION CACHE


module instr_cache(
    input  [31:0] pc,
    output [31:0] instruction
);

reg [31:0] memory [0:63];

assign instruction = memory[pc[7:2]];

initial begin
    //$readmemh("program.hex", memory);
end

endmodule



//  DATA CACHE


module data_cache(
    input         clk,
    input         mem_read,
    input         mem_write,
    input  [31:0] addr,
    input  [31:0] write_data,
    output reg [31:0] read_data
);

reg [31:0] memory [0:63];

always @(posedge clk) begin
    if(mem_write) memory[addr[7:2]] <= write_data;
end

always @(*) begin
    if(mem_read) read_data = memory[addr[7:2]];
    else         read_data = 32'b0;
end

endmodule



//  REGISTER FILE


module reg_file(
    input         clk,
    input         RegWrite,
    input  [4:0]  rs1,
    input  [4:0]  rs2,
    input  [4:0]  rd,
    input  [31:0] write_data,
    output [31:0] read_data1,
    output [31:0] read_data2
);
  



reg [31:0] registers [31:0];
  integer i;

initial begin
    for(i=0;i<32;i=i+1)
        registers[i] = 0;
end

assign read_data1 = (rs1 == 5'b0) ? 32'b0 : registers[rs1];
assign read_data2 = (rs2 == 5'b0) ? 32'b0 : registers[rs2];

always @(posedge clk) begin
    if(RegWrite && rd != 5'b0)
        registers[rd] <= write_data;
end

endmodule



//  DECODER


module decoder(
    input  [31:0] instruction,
    output [6:0]  opcode,
    output [4:0]  rd,
    output [2:0]  funct3,
    output [4:0]  rs1,
    output [4:0]  rs2,
    output [6:0]  funct7
);

assign opcode = instruction[6:0];
assign rd     = instruction[11:7];
assign funct3 = instruction[14:12];
assign rs1    = instruction[19:15];
assign rs2    = instruction[24:20];
assign funct7 = instruction[31:25];

endmodule



//  IMMEDIATE GENERATOR


module imm_gen(
    input  [31:0] instruction,
    output reg [31:0] imm
);

wire [6:0] opcode;
assign opcode = instruction[6:0];

always @(*) begin
    case(opcode)
        7'b0010011: imm = {{20{instruction[31]}}, instruction[31:20]};
        7'b0000011: imm = {{20{instruction[31]}}, instruction[31:20]};
        7'b0100011: imm = {{20{instruction[31]}}, instruction[31:25], instruction[11:7]};
        7'b1100011: imm = {{19{instruction[31]}}, instruction[31], instruction[7],
                            instruction[30:25], instruction[11:8], 1'b0};
        7'b1101111: imm = {{11{instruction[31]}}, instruction[31], instruction[19:12],
                            instruction[20], instruction[30:21], 1'b0};
        7'b0110111: imm = {instruction[31:12], 12'b0};
        default:    imm = 32'b0;
    endcase
end

endmodule



//  CONTROL UNIT


module control_unit(
    input  [6:0] opcode,
    output reg   RegWrite,
    output reg   MemRead,
    output reg   MemWrite,
    output reg   ALUSrc,
    output reg   Branch,
    output reg   Jump,
    output reg   LUI,
    output reg   AES_EN
);

always @(*) begin
    case(opcode)
        7'b0110011: begin RegWrite=1; MemRead=0; MemWrite=0; ALUSrc=0; Branch=0; Jump=0; LUI=0; AES_EN=0; end
        7'b0010011: begin RegWrite=1; MemRead=0; MemWrite=0; ALUSrc=1; Branch=0; Jump=0; LUI=0; AES_EN=0; end
        7'b0000011: begin RegWrite=1; MemRead=1; MemWrite=0; ALUSrc=1; Branch=0; Jump=0; LUI=0; AES_EN=0; end
        7'b0100011: begin RegWrite=0; MemRead=0; MemWrite=1; ALUSrc=1; Branch=0; Jump=0; LUI=0; AES_EN=0; end
        7'b1100011: begin RegWrite=0; MemRead=0; MemWrite=0; ALUSrc=0; Branch=1; Jump=0; LUI=0; AES_EN=0; end
        7'b1101111: begin RegWrite=1; MemRead=0; MemWrite=0; ALUSrc=0; Branch=0; Jump=1; LUI=0; AES_EN=0; end
        7'b0110111: begin RegWrite=1; MemRead=0; MemWrite=0; ALUSrc=1; Branch=0; Jump=0; LUI=1; AES_EN=0; end
        7'b0001011: begin RegWrite=1; MemRead=0; MemWrite=0; ALUSrc=0; Branch=0; Jump=0; LUI=0; AES_EN=1; end
        default:    begin RegWrite=0; MemRead=0; MemWrite=0; ALUSrc=0; Branch=0; Jump=0; LUI=0; AES_EN=0; end
    endcase
end

endmodule



//  ALU CONTROL


module alu_control(
    input  [2:0] funct3,
    input  [6:0] funct7,
    input        is_rtype,
    output reg [1:0] func_class,
    output reg [1:0] shift_op,
    output reg       add_sub,
    output reg [1:0] logic_fn
);

always @(*) begin
    func_class = 2'b10; shift_op = 2'b00; add_sub = 1'b0; logic_fn = 2'b00;
    case(funct3)
        3'b000: begin func_class=2'b10; add_sub=(is_rtype)?funct7[5]:1'b0; end
        3'b010: begin func_class=2'b01; end
        3'b111: begin func_class=2'b11; logic_fn=2'b00; end
        3'b110: begin func_class=2'b11; logic_fn=2'b01; end
        3'b100: begin func_class=2'b11; logic_fn=2'b10; end
        3'b001: begin func_class=2'b00; shift_op=2'b01; end
        3'b101: begin func_class=2'b00; shift_op=funct7[5]?2'b11:2'b10; end
        default: func_class=2'b10;
    endcase
end

endmodule



//  ALU


module ALU(
    input  [31:0] x, y,
    input  [1:0]  func_class, shift_op,
    input         add_sub,
    input  [1:0]  logic_fn,
    output reg [31:0] s,
    output zero
);

wire [31:0] add_result;
assign add_result = add_sub ? (x-y) : (x+y);

always @(*) begin
    case(func_class)
        2'b00: case(shift_op)
                   2'b01: s=x<<y[4:0]; 2'b10: s=x>>y[4:0];
                   2'b11: s=$signed(x)>>>y[4:0]; default: s=x;
               endcase
        2'b01: s=($signed(x)<$signed(y))?32'b1:32'b0;
        2'b10: s=add_result;
        2'b11: case(logic_fn)
                   2'b00:s=x&y; 2'b01:s=x|y; 2'b10:s=x^y; 2'b11:s=~(x|y);
                   default:s=32'b0;
               endcase
        default: s=32'b0;
    endcase
end

assign zero = (s==32'b0);

endmodule



//  BRANCH CHECKER


module branch_checker(
    input  [31:0] rs, rt,
    input  [2:0]  funct3,
    output reg    BrTrue
);

always @(*) begin
    case(funct3)
        3'b000: BrTrue=(rs==rt);
        3'b001: BrTrue=(rs!=rt);
        3'b100: BrTrue=($signed(rs)<$signed(rt));
        3'b101: BrTrue=($signed(rs)>=$signed(rt));
        default: BrTrue=1'b0;
    endcase
end

endmodule



//  ALU SOURCE MUX


module mux_alu_src(
    input  [31:0] reg_data, imm,
    input         ALUSrc,
    output [31:0] alu_in
);

assign alu_in = ALUSrc ? imm : reg_data;

endmodule



//  WRITEBACK MUX


module mux_writeback(
    input  [31:0] alu_out, mem_out, aes_out, pc_plus4,
    input         MemRead, Jump, AES_EN,
    output [31:0] write_data
);

assign write_data = AES_EN  ? aes_out  :
                   Jump    ? pc_plus4 :
                   MemRead ? mem_out  :
                             alu_out;

endmodule



//  NEXT ADDRESS LOGIC


module next_addr(
    input  [31:0] pc, imm,
    input  [1:0]  PCSrc,
    input         BrTrue,
    output reg [31:0] next_pc
);

wire [31:0] pc_plus4    = pc + 32'd4;
wire [31:0] branch_addr = pc_plus4 + imm;
wire [31:0] jump_addr   = pc + imm;

always @(*) begin
    case(PCSrc)
        2'b00:   next_pc = pc_plus4;
        2'b01:   next_pc = BrTrue ? branch_addr : pc_plus4;
        2'b10:   next_pc = jump_addr;
        default: next_pc = pc_plus4;
    endcase
end

endmodule 