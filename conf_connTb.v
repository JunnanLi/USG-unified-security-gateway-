//=====================================================================//
//	Module name: conf connection in connection manager of UniMon;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/13(Singles' Day is time out, and triggers the event
//		of waiting for the next Singles' Day. ^-^)
//	Function outline: UniMan_v1.0
//=====================================================================//

`timescale 1ns/1ps

/**	function description:
*	1) delete an out time connection:
*		+> find flowKey according to flowID;
*		+> recycle (out-time) flowID;
*		+> calculate hash values and delete hashTb;
*		+> delete flowKTb;
*	2) add a new flow:
*		+> calculate hash values and add hashTb;
*		+> add flowKTb;
*/

module conf_connTb(
reset,
clk,
add_conn_valid,
add_conn_info,
del_conn_valid,
del_conn_info,
conn_closed_valid,
conn_closed_info,
idx_hashTb,
rdValid_hashTb,
wrValid_hashTb,
data_hashTb,
ctx_hashTb,
idx_flowKTb,
rdValid_flowKTb,
wrValid_flowKTb,
data_flowKTb,
ctx_flowKTb,
pull_freeFlowID_enable,
free_flowID,
ready,
ctrl_in_valid,
ctrl_opt,
ctrl_addr,
ctrl_data_in,
ctrl_out_valid,
ctrl_data_out
);

/*	width or depth or words info of signals
*/
parameter 	w_key = 104,		// width of flow Key (i.e., 5-tuple);
			d_hashTb = 10,		// depth of hash table;
			w_hashTb = 17,		// width of hash table, inlcude valid(1b), index of flowKTb(16b);
			w_flowKTb = 120,	// width of flowTb, include flowKey(104b), and next index(16b);
			d_flowKTb = 10,	// depth of flowKey table;
			w_ctrl = 32,			// width of ctrl data;
			w_flowID = 16,		// width of flowID;
			d_Buffer = 5,		// depth of buffer, such as, aging fifo, adding fifo...;
			words_Buffer = 32,	// words fo buffer;
			d_flowIDBuffer = 10,	// depth of free flowID buffer;
			words_flowIDBuffer = 1024,	// words of free flowID buffer;
			
			/* format of 5-tuple, used for calculating hash values */
			b_dstPort_key = 80,	// last bit of dstPort in flwo key;
			b_srcPort_key = 64,	// last bit of srcPort in flow key;
			b_dstIP_key = 32,	// last bit of dstIP in flow key ;
			b_srcIP_key = 0,	// last bit of srcIP in flow key ;

			/** format of hashTb */
			b_valid_hashTb = 16,	// last bit of valid in hashTb;
			b_idx_hashTb = 0,		// last bit(location) of the idx_info in hashTb;
			/** format of flowKTb */
			b_key_flowKTb = 16,	// last bit of flow key in flow key table;
			b_idx_flowKTb = 0,		// last bit of next index in flow key table;

			INCREASE_FLOWID = 16'd1,	// prepare for free flowID buffer;
			//MAX_FLOWID = 16'h1f;		// for test;
			MAX_FLOWID = 16'h3fe;	//16'h1fe, i.e., just 2^9 flowIDs;

input								clk;
input								reset;
input								add_conn_valid;
input		[w_key+w_flowID-1:0]	add_conn_info;
input								del_conn_valid;
input		[w_flowID-1:0]			del_conn_info;
input	 							conn_closed_valid;
input		[w_flowID-1:0]			conn_closed_info;
output	reg	[d_hashTb-1:0]			idx_hashTb;
output	reg							rdValid_hashTb;
output	reg							wrValid_hashTb;
output	reg	[w_hashTb-1:0]			data_hashTb;
input		[w_hashTb-1:0]			ctx_hashTb;
output	reg	[d_flowKTb-1:0]		idx_flowKTb;
output	reg							rdValid_flowKTb;
output	reg							wrValid_flowKTb;
output	reg	[w_flowKTb-1:0]		data_flowKTb;
input		[w_flowKTb-1:0]		ctx_flowKTb;
input								pull_freeFlowID_enable;
output	wire[w_flowID-1:0]			free_flowID;
output	reg							ready;
input								ctrl_in_valid;
input		[1:0]					ctrl_opt;
input		[31:0]					ctrl_addr;
input		[31:0]					ctrl_data_in;
output	reg							ctrl_out_valid;
output	reg	[31:0]					ctrl_data_out;


/*************************************************************************************/
/*	varialbe declaration */
/*	freeFlowID buffer
*/
reg			[w_flowID-1:0]			data_flowID;
reg									wrreq_flowID;

/*	newFlow buffer */
reg									rdreq_newFlow;
wire								empty_newFlow;
wire		[w_key+w_flowID-1:0]	ctx_newFlow;
/*	delFlow buffer */
reg									rdreq_delFlow;
wire								empty_delFlow;
wire		[w_flowID-1:0]			ctx_delFlow;
/*	closeFlow buffer */
reg									rdreq_closeFlow;
wire								empty_closeFlow;
wire		[w_flowID-1:0]			ctx_closeFlow;
/*	confInfo buffer */
reg									rdreq_confInfo;
wire								empty_confInfo;
wire		[65:0]					ctx_confInfo;


/* configuration state machine */
reg		[w_key-1:0]		flowKey_temp;
reg		[w_flowID-1:0]	flowID_temp, flowID_next;
reg		[2:0]			conf_tag;
reg		[31:0]			ctrl_add_temp, ctrl_data_in_temp;
reg		[1:0]			ctrl_opt_temp;

/*************************************************************************************/
/*	state  declaration
*	
*/
reg	[3:0]	state_conf;
parameter	IDLE_S							= 4'd0,
			PREPARE_S						= 4'd1,
			READY_S						= 4'd2,
			READ_NEWFLOW_BUFFER_S	= 4'd3,
			READ_DELFLOW_BUFFER_S	= 4'd4,
			CAL_HASH_S					= 4'd5,
			WAIT_RAM_1_S					= 4'd6,
			WAIT_RAM_2_S					= 4'd7,
			ADD_NEW_FLOW_S				= 4'd8,
			DEL_OLD_FLOW_1_S			= 4'd9,
			DEL_OLD_FLOW_2_S			= 4'd10,
			DEL_OLD_FLOW_3_S			= 4'd11,
			READ_CONFINFO_BUFFER_S	= 4'd12,
			CONF_FLOW_S					= 4'd13;

/*************************************************************************************/
/*	newFlow  fifo used to buffer requests of adding a new connection */
fifo_120_32 addFlowRequest_buffer (
  .clk(clk),      				// input wire clk
  .srst(!reset),    				// input wire srst
  .din(add_conn_info),      	// input wire [119 : 0] din
  .wr_en(add_conn_valid),  // input wire wr_en
  .rd_en(rdreq_newFlow),  	// input wire rd_en
  .dout(ctx_newFlow),   		 // output wire [119 : 0] dout
  .full(),    					// output wire full
  .empty(empty_newFlow)  	// output wire empty
);


/*************************************************************************************/
/*	delFlow  fifo used to buffer requests of del an out-time connection */
fifo_16_32 delFlow_buffer (
  .clk(clk),      				// input wire clk
  .srst(!reset),    				// input wire srst
  .din(del_conn_info),      	// input wire [119 : 0] din
  .wr_en(del_conn_valid),  // input wire wr_en
  .rd_en(rdreq_delFlow),  	// input wire rd_en
  .dout(ctx_delFlow),   		 // output wire [119 : 0] dout
  .full(),    					// output wire full
  .empty(empty_delFlow)  	// output wire empty
);

fifo_16_32 closeFlow_buffer (
  .clk(clk),      				// input wire clk
  .srst(!reset),    				// input wire srst
  .din(conn_closed_info),      	// input wire [119 : 0] din
  .wr_en(conn_closed_valid),  // input wire wr_en
  .rd_en(rdreq_closeFlow),  	// input wire rd_en
  .dout(ctx_closeFlow),   		 // output wire [119 : 0] dout
  .full(),    					// output wire full
  .empty(empty_closeFlow)  	// output wire empty
);

/**********************************************************************************/
/**	fifo used as free flowID buffer */
fifo_16_512 freeFlowID_buffer (
  .clk(clk),      				// input wire clk
  .srst(!reset),    				// input wire srst
  .din(data_flowID),      	// input wire [119 : 0] din
  .wr_en(wrreq_flowID),  // input wire wr_en
  .rd_en(pull_freeFlowID_enable),  	// input wire rd_en
  .dout(free_flowID),   		 // output wire [119 : 0] dout
  .full(),    					// output wire full
  .empty()  	// output wire empty
);


fifo_66_32 confInfo_buffer (
  .clk(clk),      				// input wire clk
  .srst(!reset),    				// input wire srst
  .din({ctrl_addr,ctrl_opt,ctrl_data_in}),      	// input wire [119 : 0] din
  .wr_en(ctrl_in_valid),  // input wire wr_en
  .rd_en(rdreq_confInfo),  	// input wire rd_en
  .dout(ctx_confInfo),   		 // output wire [119 : 0] dout
  .full(),    					// output wire full
  .empty(empty_confInfo)  	// output wire empty
);

/************************************************************************************/
/**	state machine used to configure hashTb, flowKTb;
*		+>add flow in hashTb and flowKTb;
*		+>del flow in hashTb and flowKTb;
*		+>support configure by UA;
*
*	-What do you usually think when you write code?
*	-Single gives me a pair of speed hands for coding, hahaha.... :)
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		ready <= 1'b0;
		wrreq_flowID <= 1'b0;
		data_flowID <= {w_flowID{1'b0}};

		rdreq_newFlow <=1'b0;
		rdreq_delFlow <= 1'b0;
		rdreq_closeFlow <= 1'b0;
		rdreq_confInfo <= 1'b0;
		idx_hashTb <= {d_hashTb{1'b0}};
		idx_flowKTb <= {d_flowKTb{1'b0}};
		rdValid_hashTb <= 1'b0;
		rdValid_flowKTb <= 1'b0;
		wrValid_hashTb <= 1'b0;
		wrValid_flowKTb <= 1'b0;
		data_hashTb <= {w_hashTb{1'b0}};
		data_flowKTb <= {w_flowKTb{1'b0}};

		conf_tag <= 3'b0;
		flowID_next <= {w_flowID{1'b0}};
		/** output singals of ctrl */
		ctrl_out_valid <= 1'b0;
		ctrl_data_out <= 32'b0;

		state_conf <= IDLE_S;
	end
	else begin
		case(state_conf)
			IDLE_S: begin
				wrreq_flowID<= 1'b0;
				data_flowID <= {w_flowID{1'b0}};
				state_conf <= PREPARE_S;
			end
			PREPARE_S: begin
				if(data_flowID == MAX_FLOWID) begin
					wrreq_flowID <= 1'b0;
					state_conf <= READY_S;
				end
				else begin
					wrreq_flowID <= 1'b1;
					data_flowID <= data_flowID + INCREASE_FLOWID;
				end
			end
			READY_S: begin
				ready <= 1'b1;
				/** initialization */
				wrValid_hashTb <= 1'b0;
				wrValid_flowKTb <= 1'b0;
				rdValid_hashTb <= 1'b0;
				rdValid_flowKTb <= 1'b0;
				if(empty_newFlow == 1'b0) begin 
				/** the priority of adding new flow is highest; */
					rdreq_newFlow <= 1'b1;
					conf_tag <= 3'd1;
					state_conf <= READ_NEWFLOW_BUFFER_S;
				end
				else if (empty_delFlow == 1'b0) begin
				/** the priority of deleting an aging flow is only higher than reading; */
					conf_tag <= 3'd2;
					rdreq_delFlow <= 1'b1;
					state_conf <= READ_DELFLOW_BUFFER_S;
				end
				else if(empty_closeFlow == 1'b0) begin
					conf_tag <= 3'd2;
					rdreq_closeFlow <= 1'b1;
					state_conf <= READ_DELFLOW_BUFFER_S;
				end
				else if(empty_confInfo == 1'b0) begin
				/** the priority of reading an entry is lowest; */
					conf_tag <= 3'd5;
					rdreq_confInfo <= 1'b1;
					state_conf <= READ_CONFINFO_BUFFER_S;
				end
				else begin
					state_conf <= READY_S;
				end
			end
			READ_NEWFLOW_BUFFER_S: begin
				rdreq_newFlow <= 1'b0;
				{flowKey_temp, flowID_temp} <= ctx_newFlow;
				state_conf <= CAL_HASH_S;
			end
			CAL_HASH_S: begin
				wrreq_flowID <= 1'b0;
				/** calculate hash value accroding to 5-tuple info. */
				idx_hashTb <= flowKey_temp[b_srcIP_key+d_hashTb-1:b_srcIP_key]^
					flowKey_temp[b_dstIP_key+d_hashTb-1:b_dstIP_key]^
					flowKey_temp[b_srcPort_key+d_hashTb-1:b_srcPort_key]^
					flowKey_temp[b_dstPort_key+d_hashTb-1:b_dstPort_key];
				rdValid_hashTb <= 1'b1;
				state_conf <= WAIT_RAM_1_S;
			end
			WAIT_RAM_1_S: begin
				rdValid_hashTb <= 1'b0;
				rdValid_flowKTb <= 1'b0;
				state_conf <= WAIT_RAM_2_S;
			end
			WAIT_RAM_2_S: begin
				case(conf_tag)
					3'd1: state_conf <= ADD_NEW_FLOW_S;
					3'd2: state_conf <= DEL_OLD_FLOW_1_S;
					3'd3: state_conf <= DEL_OLD_FLOW_2_S;
					3'd4: state_conf <= DEL_OLD_FLOW_3_S;
					3'd5: state_conf <= CONF_FLOW_S;
					3'd6: state_conf <= READY_S;
					default: state_conf <= READY_S;
				endcase
			end
			ADD_NEW_FLOW_S: begin
				wrValid_hashTb <= 1'b1;
				data_hashTb <= {1'b1, flowID_temp};
				wrValid_flowKTb <= 1'b1;
				idx_flowKTb <= flowID_temp[d_flowKTb-1:0];

				state_conf <= READY_S;
				if(ctx_hashTb[b_valid_hashTb] == 1'b1) begin 
					/** hit, just updating hashTb and add a new entry in flowKTb*/
					data_flowKTb <= {flowKey_temp,ctx_hashTb[b_idx_hashTb+w_flowID-1:b_idx_hashTb]};
				end
				else begin /** add a new entry in hashTb and  add a new entry in flowKTb */
					data_flowKTb <= {flowKey_temp, {w_flowID{1'b0}}};
				end
			end
			READ_DELFLOW_BUFFER_S: begin
				rdreq_delFlow <= 1'b0;
				rdreq_closeFlow <= 1'b0;
				if(rdreq_delFlow == 1'b1) begin
					flowID_temp <= ctx_delFlow;
					idx_flowKTb <= ctx_delFlow[d_flowKTb-1:0];
				end
				else begin
					flowID_temp <= ctx_closeFlow;
					idx_flowKTb <= ctx_closeFlow[d_flowKTb-1:0];
				end
				rdValid_flowKTb <= 1'b1;
				state_conf <= WAIT_RAM_1_S;
			end
			DEL_OLD_FLOW_1_S: begin
				if(ctx_flowKTb == {w_flowKTb{1'b0}}) begin
					/** check this entry has been deleted */
					state_conf <= READY_S;
				end
				else begin
					/** not an empty entry, recycle flowID */
					data_flowID <= idx_flowKTb;
					wrreq_flowID <= 1'b1;
				
					/** lookup hashTb to reconfigure hash chain */
					conf_tag <= 3'd3;
					flowKey_temp <= ctx_flowKTb[b_key_flowKTb+w_key-1:b_key_flowKTb];
					flowID_next <= ctx_flowKTb[b_idx_flowKTb+w_flowID-1:b_idx_flowKTb];
					state_conf <= CAL_HASH_S;
				end
			end
			DEL_OLD_FLOW_2_S: begin /** check hash table*/
				if(ctx_hashTb[b_idx_hashTb+w_flowID-1:b_idx_hashTb] == flowID_temp) begin
					/** find the specific entry, then update hashTb */
					wrValid_hashTb <= 1'b1;
					if(flowID_next == {w_flowID{1'b0}}) begin
						/** is the only node, then delete this hash entry */
						data_hashTb <= {w_hashTb{1'b0}};
					end
					else begin
						/** point to the next node */
						data_hashTb <= {1'b1, flowID_next};
					end
					state_conf <= READY_S;
				end
				else begin
					/** lookup hash chain in flowTb */
					conf_tag <= 3'd4;
					rdValid_flowKTb <= 1'b1;
					idx_flowKTb <= ctx_hashTb[d_flowKTb-1:0];
					state_conf <= WAIT_RAM_1_S;
				end
			end
			DEL_OLD_FLOW_3_S: begin /** check flow key table */
				if(ctx_flowKTb[b_idx_hashTb+w_flowID-1:b_idx_hashTb] == flowID_temp) begin
					/** hit, and then update (point to next node) */
					wrValid_flowKTb <= 1'b1;
					data_flowKTb <= {ctx_flowKTb[b_key_flowKTb+w_key-1:b_key_flowKTb],
						flowID_next};
					state_conf <= READY_S;
				end
				else begin
					if(ctx_flowKTb[b_idx_hashTb+w_flowID-1:b_idx_hashTb] == {w_flowID{1'b0}}) 
						/** miss */
						state_conf <= READY_S;
					else begin 
						/** continue to lookup */
						rdValid_flowKTb <= 1'b1;
						idx_flowKTb <= ctx_flowKTb[d_flowKTb-1:0];
						state_conf <= WAIT_RAM_1_S;
					end
				end
			end
			READ_CONFINFO_BUFFER_S: begin
				rdreq_confInfo <= 1'b0;
				idx_flowKTb <= ctx_confInfo[33+d_flowKTb:34];
				ctrl_data_in_temp <= ctx_confInfo[31:0];
				rdValid_flowKTb <= 1'b1;
				state_conf <= WAIT_RAM_1_S;
			end
			CONF_FLOW_S: begin
				// conf flowKTb, TO DO...;
				state_conf <= READY_S;
			end
			default: begin
				state_conf <= READY_S;
			end
		endcase
	end
end


endmodule    
