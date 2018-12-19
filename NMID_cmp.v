//===============================================================//
//	Module name: NMID comparer for FAST2.0;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/15 (_zZ asdfghjkllllllllllllllllllllllllllllllllllllllllll)
//	Function outline: USG_v0.1
//===============================================================//

`timescale 1ns/1ps

module NMID_cmp(
	clk,
	reset,
	pktin_data_wr,
	pktin_data,
	pktin_data_wr_p,
	pktin_data_p,
	pktout_data_wr_p,
	pktout_data_p,
	pktout_data_wr,
	pktout_data
);
/*	width or depth or words info. of signals
*/
parameter 	LMID = 7,			// lmid of firewall;
			w_pkt = 134;		// the width of packet if FAST2.0;

input								clk;
input								reset;
input								pktin_data_wr;
input			[w_pkt-1:0]			pktin_data;
input								pktin_data_wr_p;
input			[w_pkt-1:0]			pktin_data_p;
output	reg							pktout_data_wr_p;	
output	reg		[w_pkt-1:0]			pktout_data_p;
output	reg							pktout_data_wr;
output	reg		[w_pkt-1:0]			pktout_data;



/*************************************************************************************/
/***	varialbe declaration */
/** FIFOs used to buffer packet, pfv, 
*	and fifo_1 used to buffer packets returned from function module,
*	while fifo_2 used to buffer packets whose NMID not equal to LMID;
*/
reg						rdreq_pkt_1, rdreq_pkt_2;
reg 						wrreq_pkt_2;
reg 		[w_pkt-1:0]		data_pkt_2;
wire	[w_pkt-1:0]		q_pkt_1, q_pkt_2;
wire					empty_pkt_1, empty_pkt_2;

/** temps: '1' represent NMID not equal to LMID*/
reg 						unequalTag;

/** states */
reg		[3:0]			state_output;
parameter		IDLE_S				= 4'd0,
				READ_FIFO_S		= 4'd1,
				WAIT_PKT_TAIL_S	= 4'd2;




/*************************************************************************************/
/** if module_bitmap[LMID] is '1', sending the packet to the function module*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		pktout_data_wr_p <= 1'b0;
		pktout_data_p <= {w_pkt{1'b0}};
		wrreq_pkt_2 <= 1'b0;
		data_pkt_2 <= {w_pkt{1'b0}};
		unequalTag <= 1'b0;
	end
	else begin
		// wait for packet's header;
		if((pktin_data_wr == 1'b1) && (pktin_data[133:132] == 2'b01)) begin
			if(pktin_data[26+LMID] == 1'b1) begin // valid, send to function module;
				pktout_data_wr_p <= 1'b1;
				unequalTag <= 1'b0;
			end
			else begin // not equal;
				wrreq_pkt_2 <= 1'b1;
				unequalTag <= 1'b1;
			end
		end
		else begin // data except packet's header;
			pktout_data_wr_p <= pktin_data_wr & ~unequalTag;
			wrreq_pkt_2 <= pktin_data_wr & unequalTag;
		end	
		pktout_data_p <= pktin_data;
		data_pkt_2 <= pktin_data;
	end
end
/*************************************************************************************/
/** state for output packets */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		pktout_data_wr <= 1'b0;
		pktout_data <= {w_pkt{1'b0}};
		// intermediate register inilization;
		rdreq_pkt_1 <= 1'b0;
		rdreq_pkt_2 <= 1'b0;
		// state inilizaition;
		state_output <= IDLE_S;
	end
	else begin
		case(state_output)
			IDLE_S: begin
				// initialization;
				pktout_data_wr <= 1'b0;
				// fifo is not empty and (output is ready);
				if(empty_pkt_2 == 1'b0) begin
					rdreq_pkt_2 <= 1'b1;
					state_output <= READ_FIFO_S;
				end
				else if(empty_pkt_1 == 1'b0)  begin
					rdreq_pkt_1 <= 1'b1;
					state_output <= READ_FIFO_S;
				end
				else begin
					state_output <= IDLE_S;
				end
			end
			READ_FIFO_S: begin
				pktout_data_wr <= 1'b1;
				if(rdreq_pkt_1 == 1'b1) begin
					pktout_data <= q_pkt_1;
				end
				else begin
					pktout_data <= q_pkt_2;
				end
				state_output <= WAIT_PKT_TAIL_S;
			end
			WAIT_PKT_TAIL_S: begin
				pktout_data_wr <= 1'b1;
				if(rdreq_pkt_1 == 1'b1) pktout_data <= q_pkt_1;
				else pktout_data <= q_pkt_2;
				/** state */
				if((q_pkt_1[133:132] == 2'b10) && (rdreq_pkt_1 == 1'b1)) begin
					rdreq_pkt_1 <= 1'b0;
					rdreq_pkt_2 <= 1'b0;
					state_output <= IDLE_S;
				end
				else if((q_pkt_2[133:132] == 2'b10) && (rdreq_pkt_2 == 1'b1)) begin
					rdreq_pkt_1 <= 1'b0;
					rdreq_pkt_2 <= 1'b0;
					state_output <= IDLE_S;
				end
				else begin
					state_output <= WAIT_PKT_TAIL_S;
				end
			end
			default: begin
				state_output <= IDLE_S;
			end
		endcase
	end
end

/*** submodules */
fifo_134_256 pkt_buffer_1 (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(pktin_data_p),                	// input wire [133 : 0] din
  .wr_en(pktin_data_wr_p),      	// input wire wr_en
  .rd_en(rdreq_pkt_1),            	// input wire rd_en
  .dout(q_pkt_1),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_pkt_1)           	 // output wire empty
  //.data_count()  				// output wire [7 : 0] data_count
);

fifo_134_256 pkt_buffer_2 (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(data_pkt_2),                	// input wire [133 : 0] din
  .wr_en(wrreq_pkt_2),      	// input wire wr_en
  .rd_en(rdreq_pkt_2),            	// input wire rd_en
  .dout(q_pkt_2),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_pkt_2)           	 // output wire empty
  //.data_count()  				// output wire [7 : 0] data_count
);




endmodule    
