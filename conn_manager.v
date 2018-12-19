//===============================================================//
//	Module name: connection manager of UniMan;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/11 (Happy Singles' Day, Je t'attendrai toujours.)
//	Function outline: UniMan_v1.0
//===============================================================//

`timescale 1ns/1ps

/*	function description:
*	1) extract 5-tuple in the metadata, we assurme the location of 5-tuple
*		is metadata[207:104], content length is [103:88], tcp flag is [87:80], 
*		send_seq is [79:48], ack_seq is [47:16], and window is [15:0];
*	2) calculate hash value used to search hash tables, the hash
*		functions are: a) flow_key[95:80]^[79:64]^[47:32]^[15:0];
*	3) search the flowKey table according to the result of hash table;
*	5) if hitting, return the entryID (i.e., connID); if missing, adding a new
*		flowKey entry by hardware itself (only for SYN packet);
*	6) updating current matched connection or adding a new connection;
*	7) in the mean time, updating agingTb with current timestamp.
*/
module connection_manager(
reset,
clk,
metadata_in_valid,
metadata_in,
action_valid,
action,
eventInfo_valid,
eventInfo,
idx_hashTb_search,
idx_hashTb_conf,
rdValid_hashTb_search,
rdValid_hashTb_conf,
wrValid_hashTb_conf,
data_hashTb_conf,
ctx_hashTb_search,
ctx_hashTb_conf,
idx_flowKTb_search,
idx_flowKTb_conf,
rdValid_flowKTb_search,
rdValid_flowKTb_conf,
wrValid_flowKTb_conf,
data_flowKTb_conf,
ctx_flowKTb_search,
ctx_flowKTb_conf,
idx_connTb_search,
idx_connTb_conf,
data_connTb_conf,
rdValid_connTb_search,
wrValid_connTb_conf,
ctx_connTb_search,
del_conn_valid,
del_conn_info,
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
parameter 	w_meta = 209,		// width of metadata;
			w_eventInfo = 16,	// width of eventInfo;
			w_key = 104,		// width of flow key;
			w_tcpFlag = 8,		// width of tcp flag, top 2-bit is pad;
			w_evb = 8,			// width of event bitmap; 
			w_connTb = 72,		// the width of connTb(table) entry, (4b clientState, 
								//	32b sendSeq, 4b serverState, 32b sendSeq;
			w_flowKTb = 120,	// the width of flowKTb, (104b flowK+16b index);
			d_connTb = 10,		// depth of connTb;
			d_flowKTb = 10,	// depth of flowKTb;
			w_hashTb = 17,		// the width of hashTb entry (1b valid + 16b flowKTb_index);
			d_hashTb = 10,		// depth of hashTb;
			w_flowKIdx_info = 16,	// width of flowKey_idx_info, i.e., flowKTb_index;
			w_connIdx_info = 19,	// width of conn_idx_info, includes hitness, addness,
									//	direction, and connection_index;
			w_flowID = 16,		// width of flowID;

			b_hit_meta = 208,		// last bit of hitness in metadata;
			b_flowKey_meta = 104,	// last bit of flowKey in metadata;
			b_tcpFlag_meta = 80,	// last bit of tcp flag in metadata;
			b_sendSeq_meta = 48,	// last bit of sendSeq in metadata;
			b_ackSeq_meta = 16,	// last bit of ackSeq in metadata;
			b_window_meta = 0,	// last bit of window in metadata;
			b_tcpInfo_meta = 0,	// last bit of tcp info. in metadata;
			w_tcpInfo = 72;			// width of tcp info., includes tcp flag, send seq, ack seq
		

input								clk;
input								reset;
input								metadata_in_valid;
input			[w_meta-1:0]		metadata_in;
output	wire						action_valid;
output	wire						action;
output	wire						eventInfo_valid;
output	wire	[w_eventInfo-1:0]	eventInfo;
output	wire	[d_hashTb-1:0]		idx_hashTb_search;
output	wire	[d_hashTb-1:0]		idx_hashTb_conf;
output	wire						rdValid_hashTb_search;
output	wire						rdValid_hashTb_conf;
output	wire						wrValid_hashTb_conf;
output	wire	[w_hashTb-1:0]		data_hashTb_conf;
input			[w_hashTb-1:0]		ctx_hashTb_search;
input			[w_hashTb-1:0]		ctx_hashTb_conf;
output	wire	[d_flowKTb-1:0]	idx_flowKTb_search;
output	wire	[d_flowKTb-1:0]	idx_flowKTb_conf;
output	wire						rdValid_flowKTb_search;
output	wire						rdValid_flowKTb_conf;
output	wire						wrValid_flowKTb_conf;
output	wire	[w_flowKTb-1:0]	data_flowKTb_conf;
input			[w_flowKTb-1:0]	ctx_flowKTb_search;
input			[w_flowKTb-1:0]	ctx_flowKTb_conf;
output	wire	[d_connTb-1:0]		idx_connTb_search;
output	wire	[d_connTb-1:0]		idx_connTb_conf;
output	wire	[w_connTb-1:0]		data_connTb_conf;
output	wire						rdValid_connTb_search;
output	wire						wrValid_connTb_conf;
input	wire	[w_connTb-1:0]		ctx_connTb_search;
input								del_conn_valid;
input			[w_flowID-1:0]		del_conn_info;
output	wire						ready;
input								ctrl_in_valid;
input			[1:0]				ctrl_opt;
input			[31:0]				ctrl_addr;
input			[31:0]				ctrl_data_in;
output	wire						ctrl_out_valid;
output	wire	[31:0]				ctrl_data_out;

/*************************************************************************************/
/**	varialbe declaration */
/**	from lookup_hashTb to lookup_flowKTb */
wire							flowK_idx_valid;
wire	[w_flowKIdx_info-1:0]	flowK_idx_info;

/**	from lookup_flowKTb to lookup_connTb */
wire							conn_idx_valid;
wire	[w_connIdx_info-1:0]	conn_idx_info;


/**	from lookup_flowKTb to conf_connTb */
wire							add_conn_valid;
wire	[w_key+w_flowID-1:0]	add_conn_info;
wire							pull_freeFlowID_enable;
wire	[w_flowID-1:0]			free_flowID;

/** from lookup_connTb to conf_connTb */
wire							conn_closed_valid;
wire	[w_flowID-1:0]			conn_closed_info;

/*************************************************************************************/
/*	submodule declaration */	

/*************************************************************************************/
/**	lookup_hashTb is used to lookup hashTb, and then get flowKey_idx;
*	if hashTb miss, flowKey_idx will be assigned '0';
*/
lookup_hashTb lookup_hashTb(
.clk(clk),
.reset(reset),
.metadata_in_valid(metadata_in_valid),
.metadata_in(metadata_in[b_flowKey_meta+w_key-1:b_flowKey_meta]),
.hashV(idx_hashTb_search),
.hashV_valid(rdValid_hashTb_search),
.ctx_hashTb(ctx_hashTb_search),
.flowK_idx_valid(flowK_idx_valid),
.flowK_idx_info(flowK_idx_info)
);

/*************************************************************************************/
/**	used lookup flowKTb, and then get conn_idx;
*	if flowKTb miss, conn_idx will be assigned '0';
*	there have top three bits used to represnet hitness, addness, and direction.
*/
lookup_flowKTb lookup_flowKTb(
.clk(clk),
.reset(reset),
.metadata_in_valid(metadata_in_valid),
.metadata_in({metadata_in[b_hit_meta], metadata_in[b_flowKey_meta+w_key-1:b_flowKey_meta],
	metadata_in[b_tcpFlag_meta+w_tcpFlag-1:b_tcpFlag_meta]}),
.flowK_idx_valid(flowK_idx_valid),
.flowK_idx_info(flowK_idx_info),
.idx_flowKTb(idx_flowKTb_search),
.rdValid_flowKTb(rdValid_flowKTb_search),
.ctx_flowKTb(ctx_flowKTb_search),
.conn_idx_valid(conn_idx_valid),
.conn_idx_info(conn_idx_info),
.conn_add_valid(add_conn_valid),
.conn_add_info(add_conn_info),
.pull_freeFlowID_enable(pull_freeFlowID_enable),
.free_flowID(free_flowID)
);

/*************************************************************************************/
/**	used lookup and update connTb */
lookup_connTb lookup_connTb(
.clk(clk),
.reset(reset),
.metadata_in_valid(metadata_in_valid),
.metadata_in(metadata_in[b_ackSeq_meta+w_tcpInfo-1:b_ackSeq_meta]),
.conn_idx_valid(conn_idx_valid),
.conn_idx_info(conn_idx_info),
.idx_connTb_search(idx_connTb_search),
.idx_connTb_conf(idx_connTb_conf),
.rdValid_connTb_search(rdValid_connTb_search),
.wrValid_connTb_conf(wrValid_connTb_conf),
.data_connTb_conf(data_connTb_conf),
.ctx_connTb_search(ctx_connTb_search),
.action_valid(action_valid),
.action(action),
.eventInfo_valid(eventInfo_valid),
.eventInfo(eventInfo),
.conn_closed_valid(conn_closed_valid),
.conn_closed_info(conn_closed_info)
);

/*************************************************************************************/
/**	used add and delete connection */
conf_connTb conf_connTb(
.clk(clk),
.reset(reset),
.add_conn_valid(add_conn_valid),
.add_conn_info(add_conn_info),
.del_conn_valid(del_conn_valid),
.del_conn_info(del_conn_info),
.conn_closed_valid(conn_closed_valid),
.conn_closed_info(conn_closed_info),
.idx_hashTb(idx_hashTb_conf),
.rdValid_hashTb(rdValid_hashTb_conf),
.wrValid_hashTb(wrValid_hashTb_conf),
.data_hashTb(data_hashTb_conf),
.ctx_hashTb(ctx_hashTb_conf),
.idx_flowKTb(idx_flowKTb_conf),
.rdValid_flowKTb(rdValid_flowKTb_conf),
.wrValid_flowKTb(wrValid_flowKTb_conf),
.data_flowKTb(data_flowKTb_conf),
.ctx_flowKTb(ctx_flowKTb_conf),
.pull_freeFlowID_enable(pull_freeFlowID_enable),
.free_flowID(free_flowID),
.ready(ready),
.ctrl_in_valid(ctrl_in_valid),
.ctrl_opt(),
.ctrl_addr(),
.ctrl_data_in(),
.ctrl_out_valid(),
.ctrl_data_out()
);

endmodule    
