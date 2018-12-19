//=========================================================//
//         Module name: UM
//          Communication with lijunnan (lijunnan@nudt.edu.cn)
//          Last edited time: 2018/10/17
//          Function outline: 1to2 and 2to1
//=========================================================//



module um #(
	parameter    PLATFORM = "Xilinx"
)(
	input clk,
	input [63:0] um_timestamp,
	input rst_n,
    
//cpu or port
input  pktin_data_wr,
input  [133:0] pktin_data,
input  pktin_data_valid,
input  pktin_data_valid_wr,
output wire pktin_ready,//pktin_ready = um2port_alf
    
output wire pktout_data_wr,
output wire [133:0] pktout_data,
output wire pktout_data_valid,
output wire pktout_data_valid_wr,
input pktout_ready,//pktout_ready = port2um_alf    

//control path
input [133:0] dma2um_data,
input dma2um_data_wr,
output wire um2dma_ready,

output wire [133:0] um2dma_data,
output wire um2dma_data_wr,
input dma2um_ready,
    //(*mark_debug = "true"*)    	
	//to match
	output reg um2me_key_wr,
	output reg um2me_key_valid,
	output reg [511:0] um2match_key,
	input um2me_ready,//um2me_ready = ~match2um_key_alful

	//from match
	input me2um_id_wr,
	input [15:0] match2um_id,
	output reg um2match_gme_alful,
	//localbus
	input ctrl_valid,  
	input ctrl2um_cs_n,
	output reg um2ctrl_ack_n,
	input ctrl_cmd,//ctrl2um_rd_wr,//0 write 1:read
	input [31:0] ctrl_datain,//ctrl2um_data_in,
	input [31:0] ctrl_addr,//ctrl2um_addr,
	output wire [31:0] ctrl_dataout//um2ctrl_data_out
);
 


/*********************************************************/
/**state for initializing UM2GEM*/
always @(posedge clk or negedge rst_n) begin
	if (!rst_n) begin
	// reset
		um2match_gme_alful <= 1'b0;
		um2me_key_wr <= 1'b0;
		um2me_key_valid <= 1'b0;
		um2match_key <= 512'b0;
		um2ctrl_ack_n <= 1'b1;
	end
	else begin
	end
end

usg_top usg(
.clk(clk),
.reset(rst_n),
.pktin_data_wr(pktin_data_wr),
.pktin_data(pktin_data),
.pktin_data_valid_wr(pktin_data_valid_wr),
.pktin_data_valid(pktin_data_valid),
.pktin_ready(pktin_ready),
.pktout_data_wr(pktout_data_wr),
.pktout_data(pktout_data),
.pktout_data_valid_wr(pktout_data_valid_wr),
.pktout_data_valid(pktout_data_valid),
.pktout_ready(pktout_ready),

.cin_data_wr(dma2um_data_wr),
.cin_data(dma2um_data),
.cin_ready(um2dma_ready),
.cout_data_wr(um2dma_data_wr),
.cout_data(um2dma_data),
.cout_ready(dma2um_ready)
);

endmodule    