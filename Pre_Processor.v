//===============================================================//
//	Module name: Pre_Processor for Unified Security Gateway (USG);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/12/14 (The coding cost is equal to the maximun 
//		loss druing the coding period, so you owe me a girlfriend.)
//	Function outline: USG_v1.2
//===============================================================//

`timescale 1ns/1ps

/***funciton description:
*		data processing:
*			1) write the egressPort accroding to the ingressPort;
*		control signal processing:
*			1) without any processing;
*/

module Pre_Processor(
	clk,
	reset,

	pktin_data_wr,
	pktin_data,
	pktin_ready,
	pktout_data_wr,
	pktout_data,
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
parameter 	LMID = 6,			// mid of Pre_Processor;
			w_pkt = 134,		// the width of packet if FAST2.0;
			w_5tuple = 104,		// width of 5-tuple info., i.e., protocol, dstPort, srcPort, dstIP, srcIP;
			w_key = 104;

input								clk;
input								reset;
input								pktin_data_wr;
input			[w_pkt-1:0]			pktin_data;
output	reg							pktin_ready;
output	reg							pktout_data_wr;
output	reg		[w_pkt-1:0]			pktout_data;
input								pktout_ready;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	wire						cin_ready;
output	wire						cout_data_wr;
output	wire	[w_pkt-1:0]			cout_data;
input								cout_ready;

integer i;


/** fifo used to buffer pathID (bitmap) */
wire					pathID_valid;
wire	[15:0]			pathID;

/** interactive between Pre_process and TCAM */
reg 		[w_key-1:0]		key;
reg 						key_valid;
wire 					key_ready;
wire 					ruleID_valid;
wire 	[15:0]			ruleID;
wire 					hit;

wire	[133:0]			cin_data_p2m;
wire					cin_data_wr_p2m;
wire					cin_ready_m2p;

reg 		[1:0]			pkt_count;

/** fifo used to buffer 5-tuple */
reg 		[w_key-1:0]		data_5tuple;
reg 						rdreq_5tuple, wrreq_5tuple;
wire 					empty_5tuple;
wire 	[w_key-1:0]		q_5tuple;

/** fifo used to buffer pkt */
reg 						rdreq_pkt;
wire 					empty_pkt;
wire 	[w_pkt-1:0]		q_pkt;
wire 	[7:0]			usedw_pkt;

/** fifo used to buffer pkt */
reg 						rdreq_pathID;
wire 					empty_pathID;
wire 	[15:0]			q_pathID, q_ruleID;

/** states */
reg		[3:0]			state_lookup, state_proc;
parameter	IDLE_S				= 4'd0,
			READ_FIFO_S		= 4'd1,
			WAIT_PKT_TAIL_S	= 4'd2;

fifo_104_64 tuple_buffer (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(data_5tuple),                	// input wire [133 : 0] din
  .wr_en(wrreq_5tuple),      	// input wire wr_en
  .rd_en(rdreq_5tuple),            	// input wire rd_en
  .dout(q_5tuple),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_5tuple)           	 // output wire empty
  //.data_count()  				// output wire [7 : 0] data_count
);

fifo_134_256 pkt_buffer (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(pktin_data),                	// input wire [133 : 0] din
  .wr_en(pktin_data_wr),      		// input wire wr_en
  .rd_en(rdreq_pkt),            	// input wire rd_en
  .dout(q_pkt),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_pkt),           	 // output wire empty
  .data_count(usedw_pkt)  				// output wire [7 : 0] data_count
);

fifo_16_64 pathID_buffer (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(pathID),                	// input wire [133 : 0] din
  .wr_en(pathID_valid),      	// input wire wr_en
  .rd_en(rdreq_pathID),            	// input wire rd_en
  .dout(q_pathID),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_pathID)           	 // output wire empty
  //.data_count()  				// output wire [7 : 0] data_count
);

fifo_16_64 ruleID_buffer (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(ruleID),                		// input wire [133 : 0] din
  .wr_en(ruleID_valid),      	// input wire wr_en
  .rd_en(rdreq_pathID),            	// input wire rd_en
  .dout(q_ruleID),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty()           				 // output wire empty
  //.data_count()  				// output wire [7 : 0] data_count
);

TCAM preProcessTcam(
.clk(clk),
.reset(reset),
.key_ready(key_ready),
.key_valid(key_valid),
.key(key),
.ruleID_valid(ruleID_valid),
.ruleID(ruleID),
.hit(hit),
.s_out_ready(pktout_ready),
.cin_data_wr(cin_data_wr_p2m),
.cin_data(cin_data_p2m),
.cin_ready(cin_ready_m2p),
.cout_data_wr(cout_data_wr),
.cout_data(cout_data),
.cout_ready(cout_ready)
);
defparam
	preProcessTcam.LMID = LMID;

lookup_pathID lookupPathID(
.clk(clk),
.reset(reset),
.ruleID_valid(ruleID_valid),
.ruleID(ruleID),
.hit(hit),
.pathID_valid(pathID_valid),
.pathID(pathID),
.cin_data_wr(cin_data_wr),
.cin_data(cin_data),
.cin_ready(cin_ready),
.cout_data_wr(cin_data_wr_p2m),
.cout_data(cin_data_p2m),
.cout_ready(cin_ready_m2p)
);
defparam
	lookupPathID.LMID = LMID;

//assign pktin_ready = key_ready;

/*************************************************************************************/
/** state for sending packet to TCAM */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		key_valid <= 1'b0;
		key <= {w_key{1'b0}};
		// intermediate register inilization;
		rdreq_5tuple <= 1'b0;
		// state inilizaition;
		state_lookup <= IDLE_S;
	end
	else begin
		case(state_lookup)
			IDLE_S: begin
				// initialization;
				key_valid <= 1'b0;
				key <= {w_key{1'b0}};
				if((empty_5tuple == 1'b0) && (key_ready == 1'b1)) begin
					rdreq_5tuple <= 1'b1;
					state_lookup <= READ_FIFO_S;
				end
				else begin
					rdreq_5tuple <= 1'b0;
					state_lookup <= IDLE_S;
				end
			end
			READ_FIFO_S: begin
				key_valid <= 1'b1;
				key <= q_5tuple;
				rdreq_5tuple <= 1'b0;
				state_lookup <= IDLE_S;				
			end
			default: begin
				state_lookup <= IDLE_S;
			end
		endcase
	end
end


/*************************************************************************************/
/** read pathTb */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output
		pktin_ready <= 1'b1;
		pktout_data_wr <= 1'b0;
		pktout_data <= {w_pkt{1'b0}};
		// temp;
		rdreq_pkt <= 1'b0;
		rdreq_pathID <= 1'b0;
		// state;
		state_proc <= IDLE_S;
	end
	else begin
		if(usedw_pkt < 8'd200) pktin_ready <= 1'b1;
		else pktin_ready <= 1'b0;
		case(state_proc)
			IDLE_S: begin
				pktout_data_wr <= 1'b0;
				if((empty_pathID == 1'b0)&&(pktout_ready == 1'b1)) begin
					rdreq_pkt <= 1'b1;
					rdreq_pathID <= 1'b1;
					state_proc <= READ_FIFO_S;
				end
				else
					state_proc <= IDLE_S;
			end
			READ_FIFO_S: begin
				rdreq_pathID <=1'b0;
				if(q_pkt[127] == 1'b1) begin
					/**from CPU*/
					pktout_data <= q_pkt;
					pktout_data_wr <= 1'b1;
				end
				else begin
					/** from ingress, pass or drop packets */
					if(q_pathID[0] == 1'b1) pktout_data_wr <= 1'b0;
					else pktout_data_wr <= 1'b1;
					/** modify egressPort */
					if(q_pkt[120] == 1'b0) 
						pktout_data <= {q_pkt[133:120], 8'd1, q_pkt[111:64],q_ruleID[13:0],2'b0,q_pathID,q_pkt[31:0]};
					else 
						pktout_data <= {q_pkt[133:120], 8'd0, q_pkt[111:64],q_ruleID[13:0],2'b0,q_pathID,q_pkt[31:0]};
				end
				state_proc <= WAIT_PKT_TAIL_S;
			end
			WAIT_PKT_TAIL_S: begin
				if(q_pkt[133:132] == 2'b10) begin
					state_proc <= IDLE_S;
					rdreq_pkt <= 1'b0;
				end
				else begin
					state_proc <= WAIT_PKT_TAIL_S;
				end
				pktout_data <= q_pkt;
			end
			default: begin
				state_proc <= IDLE_S;
			end
		endcase
	end
end

/** input fiveTuple */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		wrreq_5tuple <= 1'b0;
		data_5tuple <= {w_key{1'b0}};
		pkt_count <= 2'b0;		
	end
	else begin
		if(pktin_data_wr == 1'b1) begin
			if(pktin_data[133:132] == 2'b01) begin 
				pkt_count <= 2'd1;
				wrreq_5tuple <= 1'b0;
			end
			else if(pkt_count == 2'd1) begin
				wrreq_5tuple <= 1'b1;
				data_5tuple <= pktin_data[w_key-1:0];
				pkt_count <= 2'd0;
			end
			else begin
				wrreq_5tuple <= 1'b0;
			end
		end
		else begin
			wrreq_5tuple <= 1'b0;
		end
	end
end


endmodule    