//===============================================================//
//	Module name: top module of Uniman;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/28
//	Function outline: UniMan_v1.1
//===============================================================//

`timescale 1ns/1ps

module uniman_top(
	clk,
	reset,

	metadata_in_valid,
	metadata_in,
	action_valid,
	action,
	eventInfo_valid,
	eventInfo,
	ready,

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
parameter 	LMID = 8,			// lmid of firewall;
			w_pkt = 134,		// the width of packet if FAST2.0;
			w_meta = 209,		// width of metadata_in,  includes 1b hitness(allowTb),104b five-tuple information, 
								//	16b content length, 8b tcp flag, 32b send seq, 32b ack seq, 16b window;
			
			w_eventInfo = 16,		// the width of eventInfo, include 8b Event_bitmap, and 8b cliState_serState;
			w_key = 104,			// the width of flow key;
			w_evb = 8,				// the width of event bitmap;
			w_connTb = 72,			// the width of connTb(table) entry, includes 4b clientState, 
									//	32b sendSeq, 4b serverState, 32b sendSeq;
			d_connTb = 10,			// the depth of connTb;
			words_connTb = 1024,	// the words of connTb;
			w_flowKTb = 120,		// the width of flowKTb, (104b flowK+16b next index);
			d_flowKTb = 10,		// the depth of flowKTb;
			words_flowKTb = 1024,	// the words of flowKTb;
			w_agingTb = 17,		// the width of agingTb entry, (1b valid + 16b timestamp);
			w_hashTb = 17,			// the width of hashTb entry (1b valid + 16b flowKTb_index);
			d_hashTb = 10,			// the depth of hashTb;
			words_hashTb = 1024,	// the words of hashTb;
			w_timestamp = 16,		// the width of timestamp;
			w_flowID = 16,			// width of flowID;
			w_agingInfo = 16,		// width of agingInfo (i.e., entryID);

			/* constant/static parameter */
			INTERVAL_EQUAL_100MS = 32'd125000000, 	//32'd12500000,	
															// interval's clocks 12_500_000;
			INCREASE_TIME_TMP = 16'd1;	// added cur_timestamp by per time;

input								clk;
input								reset;
input								metadata_in_valid;
input			[w_meta-1:0]		metadata_in;
output	wire						action_valid;
output	wire						action;
output	wire						eventInfo_valid;
output	wire	[w_eventInfo-1:0]	eventInfo;
output	wire						ready;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	reg							cin_ready;
output	reg							cout_data_wr;
output	reg		[w_pkt-1:0]			cout_data;
input								cout_ready;


/*************************************************************************************/
/**	varialbe declaration */
/**	hash table, i.e., hashTb;
*		one port is used for searching by lookup_hashTb module;
*		another port is used as add\del operation by conf_connTb module;
*/
wire			[d_hashTb-1:0]		idx_hashTb_search, idx_hashTb_conf;
wire			[w_hashTb-1:0]		data_hashTb_conf;
wire								rden_hashTb_search, rden_hashTb_conf;
wire								wren_hashTb_conf;
wire			[w_hashTb-1:0]		ctx_hashTb_search, ctx_hashTb_conf;

/**	flowKey table, i.e., flowKTb;
*		one port is used for searching by lookup_flowKTb module;
*		another port is used as add\del operation by conf_connTb module and
*			confiruge by UA (do not support by this version);
*/
wire			[d_flowKTb-1:0]	idx_flowKTb_search, idx_flowKTb_conf;
wire			[w_flowKTb-1:0]	data_flowKTb_conf;
wire								rden_flowKTb_search, rden_flowKTb_conf;
wire								wren_flowKTb_conf;
wire			[w_flowKTb-1:0]	ctx_flowKTb_search, ctx_flowKTb_conf;

/**	connection table, i.e., connTb;
*		one port is used for searching by lookup_connTb module;
*		another port is used as add operation by lookup_connTb module;
*/
wire			[d_connTb-1:0]		idx_connTb_search, idx_connTb_conf;
wire			[w_connTb-1:0]		data_connTb_conf;
wire								rden_connTb_search;
wire								wren_connTb_conf;
wire			[w_connTb-1:0]		ctx_connTb_search;

/**	aging table, i.e., agingTb;
*		one port is used for searching\updating by outTime_inspect module;
*		another port is used for updating by lookup_connTb module;
*/
wire	[d_connTb-1:0]		idx_agingTb_aging;
wire	[w_agingTb-1:0]	data_agingTb_aging;
wire						rden_agingTb_aging;
wire						wren_agingTb_aging;// wren_agingTb_conf;
wire	[w_agingTb-1:0]	ctx_agingTb_aging;

/**	from connection_outTime to conneciton manager;
*/
wire						agingInfo_valid;
wire	[w_agingInfo-1:0]	agingInfo;

/**	timer */
reg		[31:0]				timer;
reg		[w_timestamp-1:0]	cur_timestamp;

/*************************************************************************************/
/*	submodular declaration
*	the function of conncetion_manager  is:
*		+> gets 5-tuple flow key, and calculates hash value to searh hash table; 
*		+> searches the flowKTb to find the matched entry; 
*		+> lookups connection table and gets current flow's  state, then translates
*			(updates) the conncetion state  by flow'state and current packet;
*		+> updates aging table with current timestamp.
*/
connection_manager conn_manager(
.reset(reset),
.clk(clk),
.metadata_in_valid(metadata_in_valid),
.metadata_in(metadata_in),
.action_valid(action_valid),
.action(action),
.eventInfo_valid(eventInfo_valid),
.eventInfo(eventInfo),
.idx_hashTb_search(idx_hashTb_search),
.idx_hashTb_conf(idx_hashTb_conf),
.rdValid_hashTb_search(rden_hashTb_search),
.rdValid_hashTb_conf(rden_hashTb_conf),
.wrValid_hashTb_conf(wren_hashTb_conf),
.data_hashTb_conf(data_hashTb_conf),
.ctx_hashTb_search(ctx_hashTb_search),
.ctx_hashTb_conf(ctx_hashTb_conf),
.idx_flowKTb_search(idx_flowKTb_search),
.idx_flowKTb_conf(idx_flowKTb_conf),
.rdValid_flowKTb_search(rden_flowKTb_search),
.rdValid_flowKTb_conf(rden_flowKTb_conf),
.wrValid_flowKTb_conf(wren_flowKTb_conf),
.data_flowKTb_conf(data_flowKTb_conf),
.ctx_flowKTb_search(ctx_flowKTb_search),
.ctx_flowKTb_conf(ctx_flowKTb_conf),
.idx_connTb_search(idx_connTb_search),
.idx_connTb_conf(idx_connTb_conf),
.data_connTb_conf(data_connTb_conf),
.rdValid_connTb_search(rden_connTb_search),
.wrValid_connTb_conf(wren_connTb_conf),
.ctx_connTb_search(ctx_connTb_search),
.del_conn_valid(agingInfo_valid),
.del_conn_info(agingInfo),
.ready(ready),
.ctrl_in_valid(),
.ctrl_opt(),
.ctrl_addr(),
.ctrl_data_in(),
.ctrl_out_valid(),
.ctrl_data_out()
);
defparam 
	conn_manager.w_connTb = w_connTb,
	conn_manager.w_flowKTb = w_flowKTb,
	conn_manager.w_hashTb = w_hashTb,
	conn_manager.d_connTb = d_connTb,
	conn_manager.d_flowKTb = d_flowKTb,
	conn_manager.d_hashTb = d_hashTb;


/*************************************************************************************/
/*	conn_tablle is a double-port ram, one of which is used for searching and
*		another is used for configuration;
*/
ram_72_1024 conn_table (
  .clka(clk),    // input wire clka
  .wea(1'b0),      // input wire [0 : 0] wea
  .addra(idx_connTb_search),  // input wire [7 : 0] addra
  .dina({w_connTb{1'b0}}),    // input wire [7 : 0] dina
  .douta(ctx_connTb_search),  // output wire [7 : 0] douta
  .clkb(clk),    // input wire clkb
  .web(wren_connTb_conf),      // input wire [0 : 0] web
  .addrb(idx_connTb_conf),  // input wire [7 : 0] addrb
  .dinb(data_connTb_conf),    // input wire [7 : 0] dinb
  .doutb()  // output wire [7 : 0] doutb
);


/*	aging_table is a douple-port ram, one of which is used for searching
*		and another is used for aging (and should be reseted by con-
*		figuration);
*/
ram_17_1024 aging_table (
  .clka(clk),    // input wire clka
  .wea(wren_connTb_conf),      // input wire [0 : 0] wea
  .addra(idx_connTb_conf),  // input wire [7 : 0] addra
  .dina({1'b1,cur_timestamp}),    // input wire [7 : 0] dina
  .douta(),  // output wire [7 : 0] douta
  .clkb(clk),    // input wire clkb
  .web(wren_agingTb_aging),      // input wire [0 : 0] web
  .addrb(idx_agingTb_aging),  // input wire [7 : 0] addrb
  .dinb(data_agingTb_aging),    // input wire [7 : 0] dinb
  .doutb(ctx_agingTb_aging)  // output wire [7 : 0] doutb
);

/*	hash_table is a double-port ram, one of which is used for searching
*		and another is used for configuration;
*/
ram_17_1024 hash_table (
  .clka(clk),    // input wire clka
  .wea(1'b0),      // input wire [0 : 0] wea
  .addra(idx_hashTb_search),  // input wire [7 : 0] addra
  .dina({w_hashTb{1'b0}}),    // input wire [7 : 0] dina
  .douta(ctx_hashTb_search),  // output wire [7 : 0] douta
  .clkb(clk),    // input wire clkb
  .web(wren_hashTb_conf),      // input wire [0 : 0] web
  .addrb(idx_hashTb_conf),  // input wire [7 : 0] addrb
  .dinb(data_hashTb_conf),    // input wire [7 : 0] dinb
  .doutb(ctx_hashTb_conf)  // output wire [7 : 0] doutb
);

/*	flowKey_table is a double-port ram, one of which is used for searching
*		and another is used for configuration;
*/
ram_120_1024 flowKey_table (
  .clka(clk),    // input wire clka
  .wea(1'b0),      // input wire [0 : 0] wea
  .addra(idx_flowKTb_search),  // input wire [7 : 0] addra
  .dina({w_flowKTb{1'b0}}),    // input wire [7 : 0] dina
  .douta(ctx_flowKTb_search),  // output wire [7 : 0] douta
  .clkb(clk),    // input wire clkb
  .web(wren_flowKTb_conf),      // input wire [0 : 0] web
  .addrb(idx_flowKTb_conf),  // input wire [7 : 0] addrb
  .dinb(data_flowKTb_conf),    // input wire [7 : 0] dinb
  .doutb(ctx_flowKTb_conf)  // output wire [7 : 0] doutb
);

/*************************************************************************************/
/*	connection_outTime_inspector check the connection entry whether it 
*		is outtime, and send the out-time inifo to build-in generator;
*/
connection_outTime_inspector conn_outTime_inspector(
.reset(reset),
.clk(clk),
.idx_agingTb(idx_agingTb_aging),
.data_agingTb(data_agingTb_aging),
.rdValid_agingTb(rden_agingTb_aging),
.wrValid_agingTb(wren_agingTb_aging),
.ctx_agingTb(ctx_agingTb_aging),
.agingInfo_valid(agingInfo_valid),
.agingInfo(agingInfo),
.cur_timestamp(cur_timestamp)
);


/*************************************************************************************/
/*	state machine declaration
*	this state machine is used to generate a timer; 
*/
always @ (posedge clk or negedge reset) begin
	if(!reset) begin
		cur_timestamp <= {w_timestamp{1'b0}};
		timer <= 32'b0;
	end
	else begin
		if(timer == INTERVAL_EQUAL_100MS) begin
			cur_timestamp <= cur_timestamp + INCREASE_TIME_TMP;
			timer <= 32'b0;
		end
		else begin
			timer <= timer + 32'd1;
		end
	end
end


/*************************************************************************************/
/*	this state machine is used to output cin/cout;
*/
always @ (posedge clk or negedge reset) begin
	if(!reset) begin
		cin_ready <= 1'b1;
		cout_data_wr <= 1'b0;
		cout_data <={w_pkt{1'b0}};
	end
	else begin
		cout_data_wr <= cin_data_wr;
		cout_data <= cin_data;
	end
end

endmodule    
