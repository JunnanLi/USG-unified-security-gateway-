//===============================================================//
//	Module name: Top module for Unified Security Gateway (USG);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/12/14 (rain without rainbow, just like my mood)
//	Function outline: USG_v1.2
//===============================================================//

`timescale 1ns/1ps

module usg_top(
	clk,
	reset,

/** pktin/pktout and pfvin/pfvout used as data signals
*	the width of pktin/pktout is 134b:
*		+>2b header/tail tag: 01 is header, 11 is body, and 10 is tail;
*		+>4b invalid types, e.g., 4'd0 represents none invalid type;
*		+>128b data;
*	the defination of metadata:
*	    metadata_0:
* 		+>[127] pktsrc, '1' represents recving from CPU;
*		+>[126] pktdst, '1' represents sending to CPU;
*		+>[125:120] ingressPort;
*		+>[119:118] outType; '00' is normal forwarding, '01' is muticast, '10' is broadcast;
*		+>[117:112] egressPort;
*		+>[111:109] priority; currently, we do not care;
*		+>[108] discard;
* 		+>[107:96] len;
*		+>[95:88] SMID;
*		+>[87:80] DMID;
*		+>[79:72] PST;
*		+>[71:64] seq, i.e., pktID;
*		+>[63:50] flowID, i.e., ruleID;
*		+>[49:32] reserved; pathID
*		+>[31:0] timestamp;
*	    metadata_1:
*		+>16b length of tcp content 
*		+>8b tcp flags, SYN_flood
*		+>32b send seq
*		+>32b ack seq
*		+>16b tcp window
*		+>8b window scale factor, xxx;
*		+>16b reserved;
*/
	pktin_data_wr,
	pktin_data,
	pktin_data_valid_wr,
	pktin_data_valid,
	pktin_ready,
	pktout_data_wr,
	pktout_data,
	pktout_data_valid_wr,
	pktout_data_valid,
	pktout_ready,

/**	cin/cou used as control signals 
*	the width of cin/cou is 134b:
*		+>1b([127])			ctl, i.e., 1'b1;
*		+>3b([126:124])		rd/wr, 3'b001 is rd, 3'b010 is wr, and 3'b011 is response;
*		+>12b([123:112])	seq;
*		+>8b([111:104])		smid;
*		+>8b([103:96])		dmid;
*		+>32b([95:64])		addr;
*		+>32b([63:32])		mask;
*		+>32b([31:0])		data;
*/
	cin_data_wr,
	cin_data,
	cin_ready,
	cout_data_wr,
	cout_data,
	cout_ready
);
/*	width or depth or words info. of signals
*/
parameter 	w_pkt = 134,		// the width of packet if FAST2.0;
			
			L4PAR = 0,			// L4_Parser;
			PREPRO = 1,		// Pre_process;
			SFW = 2,			// stateful firewall;
			TRANS = 3,			// transmitter;
			MAX_MODULE = 2;		

input								clk;
input								reset;
(*mark_debug = "true"*)	input								pktin_data_wr;
(*mark_debug = "true"*)	input			[w_pkt-1:0]			pktin_data;
(*mark_debug = "true"*)	input								pktin_data_valid_wr;
(*mark_debug = "true"*)	input								pktin_data_valid;
(*mark_debug = "true"*)	output	wire						pktin_ready;
(*mark_debug = "true"*)	output	wire						pktout_data_wr;
(*mark_debug = "true"*)	output	wire	[w_pkt-1:0]			pktout_data;
(*mark_debug = "true"*)	output	wire						pktout_data_valid_wr;
(*mark_debug = "true"*)	output	wire						pktout_data_valid;
(*mark_debug = "true"*)	input								pktout_ready;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	wire						cin_ready;
output	wire						cout_data_wr;
output wire		[w_pkt-1:0]			cout_data;
input								cout_ready;

/*************************************************************************************/
/***	varialbe declaration */
/**	signals used to connect sub modules, include data signals (pkt and pfv), and 
*	control/configure signals (cData);
*/
wire					pkt_data_wr[MAX_MODULE:0];
wire	[w_pkt-1:0]		pkt_data[MAX_MODULE:0];
wire 					pkt_ready[MAX_MODULE:0];
wire					cData_wr[MAX_MODULE:0];
wire	[w_pkt-1:0]		cData[MAX_MODULE:0];
wire					cData_ready[MAX_MODULE:0];

/*************************************************************************************/
/***	submodular declaration*/
/** parser, used to extract pfv (parse Ethernet, IP, ICMP, TCP/UDP, HTTP);
*	Currently, we do not support variable lenth of TCP header, and parsing option fields;
*
*	I can, but I do not want to;
*/
L4_Parser L4parser(
.clk(clk),
.reset(reset),
.pktin_data_wr(pktin_data_wr),
.pktin_data(pktin_data),
.pktin_ready(pktin_ready),
.pktout_data_wr(pkt_data_wr[L4PAR]),
.pktout_data(pkt_data[L4PAR]),
.pktout_ready(pkt_ready[L4PAR])
);
defparam
	L4parser.LMID = 1;


/** pre-Processor, used to (write the egressPort according to the ingressPort),
*	the function of providing module chain is on the way...;
*/
Pre_Processor preProcessor(
.clk(clk),
.reset(reset),
.pktin_data_wr(pkt_data_wr[PREPRO-1]),
.pktin_data(pkt_data[PREPRO-1]),
.pktin_ready(pkt_ready[PREPRO-1]),
.pktout_data_wr(pkt_data_wr[PREPRO]),
.pktout_data(pkt_data[PREPRO]),
.pktout_ready(pkt_ready[PREPRO]),
//control path
.cin_data(cin_data),
.cin_data_wr(cin_data_wr),
.cin_ready(cin_ready),
.cout_data(cData[PREPRO]),
.cout_data_wr(cData_wr[PREPRO]),
.cout_ready(cData_ready[PREPRO])
);
defparam
	preProcessor.LMID = 6;



/** stateful firewall, filter invalid packets by maintaining connections' state;
*	current, we do not provide the connection manager module;
*/
Stateful_Firewall statefulFirewall(
.clk(clk),
.reset(reset),
.pktin_data_wr(pkt_data_wr[SFW-1]),
.pktin_data(pkt_data[SFW-1]),
.pktin_ready(pkt_ready[SFW-1]),
.pktout_data_wr(pkt_data_wr[SFW]),
.pktout_data(pkt_data[SFW]),
.pktout_ready(pkt_ready[SFW]),
//control path
.cin_data(cData[SFW-1]),
.cin_data_wr(cData_wr[SFW-1]),
.cin_ready(cData_ready[SFW-1]),
.cout_data(cData[SFW]),
.cout_data_wr(cData_wr[SFW]),
.cout_ready(cData_ready[SFW])
);
defparam
	statefulFirewall.LMID = 7;


/** DPI: send matched packets to CPU, and forward packets returned back from CPU, and 
*	unmatched packets;
*/
Transmitter transmitter(
.clk(clk),
.reset(reset),
.pktin_data_wr(pkt_data_wr[TRANS-1]),
.pktin_data(pkt_data[TRANS-1]),
.pktin_ready(pkt_ready[TRANS-1]),
.pktout_data_wr(pktout_data_wr),
.pktout_data(pktout_data),
.pktout_data_valid(pktout_data_valid),
.pktout_data_valid_wr(pktout_data_valid_wr),
.pktout_ready(pktout_ready),
//control path
.cin_data(cData[TRANS-1]),
.cin_data_wr(cData_wr[TRANS-1]),
.cin_ready(cData_ready[TRANS-1]),
.cout_data(cout_data),
.cout_data_wr(cout_data_wr),
.cout_ready(cout_ready)
);
defparam
	transmitter.LMID = 8;


endmodule    
