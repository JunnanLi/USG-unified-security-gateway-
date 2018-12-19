//===============================================================//
//	Module name: ids for Unified Security Gateway (USG);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/18
//	Function outline: USG_v0.1
//===============================================================//

`timescale 1ns/1ps

module Transmitter(
	clk,
	reset,
/** pktin/pktout and pfvin/pfvout used as data signals, and the width of pktin/
*	pktout is 134b, while the width of pfvin/pfvout is 248b, includes 104b 5-tuple 
*	info., 16b length of tcp content, 8b tcp flags, 32b send seq, 32b ack seq, 16b 
*	tcp window, 8b window scale factor, and 32b HTTP type field;
*/
	pktin_data_wr,
	pktin_data,
	pktin_ready,
	pktout_data_wr,
	pktout_data,
	pktout_data_valid_wr,
	pktout_data_valid,
	pktout_ready,
/**	cin/cou used as control signals */
	cin_data_wr,
	cin_data,
	cin_ready,
	cout_data_wr,
	cout_data,
	cout_ready
);
/*	width or depth or words info. of signals
*/
parameter 	LMID = 9,			// lmid of Transmitter;
			MID_IDS_UA = 132,	// mid of IDS-UA;
			w_pkt = 134;		// the width of packet if FAST2.0;


input								clk;
input								reset;
input								pktin_data_wr;
input			[w_pkt-1:0]			pktin_data;
output	reg							pktin_ready;
output	reg		    				pktout_data_wr;	
output	reg	     [w_pkt-1:0]		pktout_data;
output	reg						    pktout_data_valid_wr;
output	reg						    pktout_data_valid;
input								pktout_ready;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	wire						cin_ready;
output	wire						cout_data_wr;
output	wire	[w_pkt-1:0]			cout_data;
input								cout_ready;


/*************************************************************************************/
/***	varialbe declaration */
/** fifo used to buffer pkt */
reg						rdreq_pkt;
wire	[w_pkt-1:0]		q_pkt;
wire					empty_pkt;
wire 	[7:0]			usedw_pkt;


/** temps: */
reg 		[w_pkt-1:0]		metadata_temp;
reg 						packetIN_tag;
/** states */
reg		[3:0]			state_proc;
parameter	IDLE_S						= 4'd0,
			READ_META_0_S			= 4'd1,
			READ_META_1_S			= 4'd2,
			WAIT_PKT_TAIL_S			= 4'd3;

/*** subModules */
fifo_134_256 pkt_buffer (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(pktin_data),                	// input wire [133 : 0] din
  .wr_en(pktin_data_wr),      	// input wire wr_en
  .rd_en(rdreq_pkt),            	// input wire rd_en
  .dout(q_pkt),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_pkt),          	 // output wire empty
  .data_count(usedw_pkt)  	// output wire [7 : 0] data_count
);

assign cout_data_wr = cin_data_wr;
assign cout_data = cin_data;
assign cin_ready = cout_ready;

/*************************************************************************************/
/** state for procing packet */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		pktout_data_wr<= 1'b0;
		pktout_data <= {w_pkt{1'b0}};
		pktout_data_valid_wr <= 1'b0;
		pktout_data_valid <= 1'b0;
		pktin_ready <= 1'b1;
		// intermediate register inilization;
		rdreq_pkt <= 1'b0;
		metadata_temp <= {w_pkt{1'b0}};
		packetIN_tag <= 1'b0;
		// state inilizaition;
		state_proc <= IDLE_S;
	end
	else begin
		if(usedw_pkt < 8'd200) pktin_ready <= 1'b1;
		else pktin_ready <= 1'b0;
		/** state_proc */
		case(state_proc)
			IDLE_S: begin
				// initialization;
				pktout_data_wr <= 1'b0;
				pktout_data_valid_wr <= 1'b0;
				/** fifo is not empty */
				if((empty_pkt == 1'b0)&&(pktout_ready == 1'b1)) begin
					rdreq_pkt <= 1'b1;
					state_proc <= READ_META_0_S;
				end
				else begin
					rdreq_pkt <= 1'b0;
					state_proc <= IDLE_S;
				end
			end
			READ_META_0_S: begin
				metadata_temp <= q_pkt;
				packetIN_tag <= q_pkt[34];
				if(q_pkt[127] == 1'b1) begin
					//pktout_data_wr <= 1'b1;
					//pktout_data <= q_pkt;
					state_proc <= READ_META_1_S;
				end
				else begin
					state_proc <= READ_META_1_S;
				end
			end
			READ_META_1_S: begin
				pktout_data_wr <= 1'b1;
				if(packetIN_tag == 1'b1) begin
					/** packet in*/
					pktout_data <= {metadata_temp[133:127],1'b1,metadata_temp[125:96],LMID[7:0],MID_IDS_UA[7:0],
						metadata_temp[79:0]};
				end
				else begin
					pktout_data <= metadata_temp;
				end
				state_proc <= WAIT_PKT_TAIL_S;
			end
			WAIT_PKT_TAIL_S: begin
				pktout_data <= q_pkt;
				if(q_pkt[133:132] == 2'b10) begin
					state_proc <= IDLE_S;
					rdreq_pkt <= 1'b0;
					pktout_data_valid_wr <= 1'b1;
					pktout_data_valid <= 1'b1;
				end
				else begin
					state_proc <= WAIT_PKT_TAIL_S;
				end
			end
			default: begin
				state_proc <= IDLE_S;
			end
		endcase
	end
end



endmodule    
