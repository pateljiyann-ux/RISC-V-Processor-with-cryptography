// Code your testbench here
// or browse Examples
`timescale 1ns/1ps

module testbench;

reg clk;
reg reset;
integer i;

// Instantiate processor
RISC DUT(
    .clk(clk),
    .reset(reset)
);


// Clock Generation


initial begin
    clk = 0;
    forever #5 clk = ~clk;   // 10ns clock
end


// Reset


initial begin
    reset = 1;
    #20;
    reset = 0;
end


// Dump waveform


initial begin
    $dumpfile("dump.vcd");
    $dumpvars(0, testbench);
end


// Monitor PC and instruction


initial begin
    $monitor("TIME=%0t PC=%h INSTR=%h ALU_OUT=%h WRITE=%h",
        $time,
        DUT.pc,
        DUT.instruction,
        DUT.alu_out,
        DUT.write_data
    );
end


// Print Register File


initial begin

    #400;   

    $display("\n=================================");
    $display("REGISTER FILE CONTENT");
    $display("=================================");

    for(i = 0; i < 32; i = i + 1) begin
        $display("x%0d = %h", i, DUT.RF.registers[i]);
    end

    $display("=================================\n");

    $finish;

end

endmodule