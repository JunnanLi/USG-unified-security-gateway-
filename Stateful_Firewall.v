//===============================================================//
//	Module name: Stateful Firewall for Unified Security Gateway (USG);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/16
//	Function outline: USG_v0.1
//===============================================================//

`timescale 1ns/1ps

module Stateful_Firewall(
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
parameter 	LMID = 8,			// lmid of stateful firewall;
			w_pkt = 134,		// the width of packet if FAST2.0;
								// 	16b content length, 8b tcpFlag, 32b sendSeq, 
								//	32b ackSeq, 16b window;
			w_tcpInfo = 208	,	// width of tcpInfo;
			w_meta = 209,		// width of metadata_in,  includes 1b hitness(allowTb), 104b five-tuple information, 
								//	16b content length, 8b tcp flag, 32b send seq, 32b ack seq, 16b window;
			b_window_pfv = 40;	// last bit of window in pfv;

input								clk;
input								reset;
input								pktin_data_wr;
input			[w_pkt-1:0]			pktin_data;
output	reg							pktin_ready;
output	wire						pktout_data_wr;	
output	wire	[w_pkt-1:0]			pktout_data;
input								pktout_ready;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	wire						cin_ready;
output	reg							cout_data_wr;
output	reg		[w_pkt-1:0]			cout_data;
input								cout_ready;


/*************************************************************************************/
/***	varialbe declaration */
/** fifo used to buffer action */
reg						rdreq_action;
wire	[1:0]			q_action;
wire					empty_action;
/** fifo used to buffer pkt */
reg						rdreq_pkt;
wire	[w_pkt-1:0]		q_pkt;
wire					empty_pkt;
wire 	[7:0]			usedw_pkt;

/** temps: */
/** interact between alllowTb and sfw */
reg						ruleID_valid;
reg		[15:0]			ruleID;
wire					hit_valid;
wire					hit;
/** interactive with uniman*/
reg						metadata_in_valid;
reg		[w_meta-1:0]	metadata_in;
wire					action_valid;
wire					action;
wire					uniman_ready;
/** interactive with NMIDcmp*/
wire					pktin_data_wr_p;
wire	[w_pkt-1:0]		pktin_data_p;
reg						pktout_data_wr_p;
reg		[w_pkt-1:0]		pktout_data_p;
/** counter used to record the number of established connnection */
reg 		[32:0]			counter_established, counter_established_set;
reg 		[32:0]			counter_closed, counter_closed_set;
wire					cout_data_wr_m;
wire	[w_pkt-1:0]		cout_data_m;
wire 					eventInfo_valid;
wire 	[15:0]			eventInfo;

/** states */
reg		[3:0]			state_proc;
parameter	IDLE_S				= 4'd0,
			READ_HIT_FIFO_S	= 4'd1,
			READ_FIFO_S		= 4'd2,
			WAIT_PKT_TAIL_S	= 4'd3,
			WRITE_META_1_S	= 4'd4,
			WRITE_META_2_S	= 4'd5,
			CHANGE_ETH_S	= 4'd6,
			CHANGE_IP_S		= 4'd7,
			CHANGE_TCP_S	= 4'd8;

reg 		[1:0]			pkt_tag;
reg 		[31:0]			srcIP_temp, dstIP_temp;
reg 		[15:0]			srcPort_temp, dstPort_temp;
reg 						action_temp, action_valid_temp;


/*** subModules */
NMID_cmp NMIDcmp(
.clk(clk),
.reset(reset),
.pktin_data_wr(pktin_data_wr),
.pktin_data(pktin_data),
.pktin_data_wr_p(pktout_data_wr_p),
.pktin_data_p(pktout_data_p),
.pktout_data_wr_p(pktin_data_wr_p),
.pktout_data_p(pktin_data_p),
.pktout_data_wr(pktout_data_wr),
.pktout_data(pktout_data)
);
defparam
	NMIDcmp.LMID = LMID;

uniman_top UniMan(
.clk(clk),
.reset(reset),
.metadata_in_valid(metadata_in_valid),
.metadata_in(metadata_in),
.action_valid(action_valid),
.action(action),
.eventInfo_valid(eventInfo_valid),
.eventInfo(eventInfo),
.ready(uniman_ready),
.cin_data_wr(),
.cin_data(),
.cin_ready(),
.cout_data_wr(),
.cout_data(),
.cout_ready()
);

 Firewall_action sfwAction(
.clk(clk),
.reset(reset),
.ruleID_valid(ruleID_valid),
.ruleID(ruleID),
.action_valid(hit_valid),
.action(hit),
.cin_data_wr(cin_data_wr),
.cin_data(cin_data),
.cin_ready(cin_ready),
.cout_data_wr(cout_data_wr_m),
.cout_data(cout_data_m),
.cout_ready(cout_ready)
);
defparam
	sfwAction.LMID = LMID;

fifo_134_256 pkt_buffer (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(pktin_data_p),                	// input wire [133 : 0] din
  .wr_en(pktin_data_wr_p),      	// input wire wr_en
  .rd_en(rdreq_pkt),            	// input wire rd_en
  .dout(q_pkt),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_pkt),         	 // output wire empty
  .data_count(usedw_pkt)  	// output wire [7 : 0] data_count
);


fifo_2_32 action_buffer (
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din({eventInfo[14],action_temp}),                	// input wire [133 : 0] din
  .wr_en(action_valid_temp),      	// input wire wr_en
  .rd_en(rdreq_action),            	// input wire rd_en
  .dout(q_action),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_action)           	 // output wire empty
  //.data_count()  				// output wire [7 : 0] data_count
);

/** maintain action and action_valid */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output
		action_valid_temp <= 1'b0;
		action_temp <= 1'b0;
	end
	else begin
		action_valid_temp <= action_valid;
		action_temp <= action;
	end
end

/** extract ruleID */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output
		ruleID_valid <= 1'b0;
		ruleID <= 16'b0;
	end
	else begin
		if((pktin_data_wr_p == 1'b1) && (pktin_data_p[133:132] == 2'b01)) begin
			ruleID_valid <= 1'b1;
			ruleID <= {2'b0,pktin_data_p[63:50]};
		end
		else begin
			ruleID_valid <= 1'b0;
		end
	end
end

/*************************************************************************************/
/** state for sending metadata to uniman */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		metadata_in_valid <= 1'b0;
		metadata_in <= {w_meta{1'b0}};
		// intermediate register inilization;
		pkt_tag <= 2'b0;
		// state inilizaition;
	end
	else begin
		if(pktin_data_wr_p == 1'b1) begin
			if(pktin_data_p[133:132] == 2'b01) pkt_tag <= 2'd1;
			else if(pkt_tag == 2'd1) begin
				metadata_in[207:104] <= pktin_data_p[103:0];
				pkt_tag <= 2'd2;
			end
			else if(pkt_tag == 2'd2) begin
				metadata_in[103:0] <= pktin_data_p[127:24];
				pkt_tag <= 2'd0;
			end
			else begin
				metadata_in[207:0] <= metadata_in[207:0];
				pkt_tag <= 2'd0;
			end

			if(hit_valid == 1'b1) begin
				metadata_in_valid <= 1'b1;
				metadata_in[208] <= hit;
			end
			else begin
				metadata_in_valid <= 1'b0;
			end
		end
		else begin
			pkt_tag <= 2'b0;
		end
	end
end

/*************************************************************************************/
/** state for procing packet according to the action returned from uniman;
*	update counter, TO DO...;
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		pktout_data_wr_p <= 1'b0;
		pktout_data_p <= {w_pkt{1'b0}};
		pktin_ready <= 1'b1;
		// intermediate register inilization;
		rdreq_action <= 1'b0;
		rdreq_pkt <= 1'b0;
		srcIP_temp <= 32'b0;
		dstIP_temp <= 32'b0;
		srcPort_temp <= 16'b0;
		dstPort_temp <= 16'b0;
		// state inilizaition;
		state_proc <= IDLE_S;
	end
	else begin
		if((pktout_ready == 1'b1)&&(usedw_pkt < 8'd200)) pktin_ready <= 1'b1;
		else pktin_ready <= 1'b0;
		case(state_proc)
			IDLE_S: begin
				// initialization;
				pktout_data_wr_p <= 1'b0;
				/** fifo is not empty */
				if((empty_action == 1'b0)&&(pktout_ready == 1'b1)) begin
				/**  read pkt_fifo*/
					rdreq_pkt <= 1'b1;
					rdreq_action <= 1'b1;
					state_proc <= READ_FIFO_S;
				end
				else begin
					state_proc <= IDLE_S;
				end
			end
			READ_FIFO_S: begin
			/** action == 1 */
				if(q_action[1] == 1'b1) begin
					pktout_data_wr_p <= 1'b1;
					if(q_pkt[120] == 1'b0) 
						pktout_data_p <= {q_pkt[133:120], 8'd0, q_pkt[111:0]};
					else 
						pktout_data_p <= {q_pkt[133:120], 8'd1, q_pkt[111:0]};
					//pktout_data_p <= q_pkt;
					state_proc <= WRITE_META_1_S;
				end
			/** action == 1 */
				else if(q_action[0] == 1'b1) begin
					pktout_data_wr_p <= 1'b1;
					pktout_data_p <= q_pkt;
					state_proc <= WAIT_PKT_TAIL_S;
				end
				else begin
					pktout_data_wr_p <= 1'b0;
					state_proc <= WAIT_PKT_TAIL_S;
				end
				rdreq_action <= 1'b0;
			end
			WAIT_PKT_TAIL_S: begin
				pktout_data_p <= q_pkt;
				if(q_pkt[133:132] == 2'b10) begin
					state_proc <= IDLE_S;
					rdreq_pkt <= 1'b0;
				end
				else begin
					state_proc <= WAIT_PKT_TAIL_S;
				end
			end
			WRITE_META_1_S: begin
				pktout_data_p <= q_pkt;
				state_proc <= WRITE_META_2_S;
				{srcPort_temp,dstPort_temp,srcIP_temp,dstIP_temp} <= q_pkt[95:0];
			end
			WRITE_META_2_S: begin
				pktout_data_p <= q_pkt;
				state_proc <= CHANGE_ETH_S;
			end
			CHANGE_ETH_S: begin
				pktout_data_p <= {q_pkt[133:128], q_pkt[79:32], q_pkt[127:80], q_pkt[31:0]};
				state_proc <= CHANGE_IP_S;
			end
			CHANGE_IP_S: begin
				pktout_data_p <= {q_pkt[133:48], dstIP_temp, srcIP_temp[31:16]};
				state_proc <= CHANGE_TCP_S;
			end
			CHANGE_TCP_S: begin
				pktout_data_p <= {q_pkt[133:128], srcIP_temp[15:0], dstPort_temp, srcPort_temp,
					q_pkt[79:8],8'd4};
				state_proc <= WAIT_PKT_TAIL_S;
			end
			default: begin
				state_proc <= IDLE_S;
			end
		endcase
	end
end


/*************************************************************************************/
/** state for counting establisehd and closed connections */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		cout_data_wr <= 1'b0;
		cout_data <= 134'b0;
		counter_established <= 33'b0;
		counter_closed <= 33'b0;
		counter_established_set <= 33'b0;
		counter_closed_set <= 33'b0;
		// intermediate register inilization;
		
		// state inilizaition;
	end
	else begin
		cout_data_wr <= cout_data_wr_m;
		if(cout_data_m[133:132] == 2'b01) begin
			/** response packet && SMID == LMID && 1th 32bit */
			if((cout_data[111:104] == LMID) && (cout_data_m[126:124] == 3'b011)&&(cout_data_m[66:64] == 3'd1))
				cout_data <= {cout_data_m[133:32], counter_established[31:0]};
			else
				cout_data <= cout_data_m;
		end
		else begin
			cout_data <= cout_data_m;
		end

		if(cin_data[133:132] == 2'b01) begin
			/** write packet and DMID == LMID */
			if((cin_data[103:96] == LMID) && (cin_data[126:124] == 3'b010)&&(cin_data[66:64] == 3'd1))
				counter_established_set <= {~counter_established_set[32], cin_data[31:0]};
			else
				counter_established_set <= counter_established_set;
		end
		else begin
			counter_established_set <= counter_established_set;
		end

		if(counter_established_set[32] == counter_established[32]) begin
			if((eventInfo_valid == 1'b1)&&(eventInfo[10] == 1'b1))
				counter_established <= counter_established + 33'd1;
			else
				counter_established <= counter_established;
		end
		else begin
			counter_established <= counter_established_set;
		end
	end
end



endmodule    
