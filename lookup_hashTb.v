//=====================================================================//
//	Module name: lookup hashTb in conneciton searcher of UniMan;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/11 (Happy Singles' Day,  Je t'attendrai toujours.)
//	Function outline: UniMan_v1.0
//=====================================================================//

`timescale 1ns/1ps

/*	function description:
*	1) extract 5-tuple in the metadata, we assurme the location of 4-tuple
*		is metadata[103:0];
*	2) calculate two hash values used to search hash tables, the hash
*		function is: flow_key[95:80]^[79:64]^[47:32]^[15:0];
*/
module lookup_hashTb(
reset,
clk,
metadata_in_valid,
metadata_in,
hashV,
hashV_valid,
ctx_hashTb,
flowK_idx_valid,
flowK_idx_info
);

/*	width or depth or words info of signals
*/
parameter 	w_meta = 104,			// width of metadata;
			w_key = 104,			// width of flow key;
			w_hashTb = 17,			// width of hashTb's entry, (1 + 16);
			d_hashTb = 10,			// depth of hashTb;
			w_flowKIdx_info = 16,	// width of conn_idx_info, i.e., flowKTb_idx;
			w_idx = 16,				// width of idx in hashTb;
			
			/** used for calculating hash values 
			*	the sequence of 5-tuple is protocol, dstport, srcport, dstip, srcip;
			*/
			b_srcIP_key = 0,		// last bit of srcIP in flow key;
			b_dstIP_key = 32,		// last bit of dstIP in flow key;
			b_srcPort_key = 64,		// last bit of srcPort in flow key;
			b_dstPort_key = 80,		// last bit of dstPort in flow key;
			b_protocol_key = 96,	// last bit fo protocol in flow key;
			/** format of hashTb*/
			b_valid_hashTb = 16,	// last bit of valid in hashTb;
			b_idx_hashTb = 0;		// last bit of the idx_info in hashTb;


input								clk;
input								reset;
input								metadata_in_valid;
input		[w_meta-1:0]			metadata_in;
output	reg	[d_hashTb-1:0]			hashV;
output	reg							hashV_valid;
input		[w_hashTb-1:0]			ctx_hashTb;
output	reg							flowK_idx_valid;
output	reg	[w_flowKIdx_info-1:0]	flowK_idx_info;


/*************************************************************************************/
/***	varialbe declaration */
/**	valid_temp is used to count clocks for waiting the result from hashTb ;
*/
reg			valid_temp[1:0];

/*************************************************************************************/
/***	state register declaration*/

/*************************************************************************************/
/***	submodule declaration */

/*************************************************************************************/
/***	state machine declaration */
/**	this state machine is used gen hash value according to the five-tuple info.;
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		valid_temp[0] <= 1'b0;
		valid_temp[1] <= 1'b0;

		hashV_valid <= 1'b0;
		hashV <= {d_hashTb{1'b0}};
	end
	else begin
		hashV <= metadata_in[b_srcIP_key+d_hashTb-1:b_srcIP_key]^
			metadata_in[b_dstIP_key+d_hashTb-1:b_dstIP_key]^
			metadata_in[b_srcPort_key+d_hashTb-1:b_srcPort_key]^
			metadata_in[b_dstPort_key+d_hashTb-1:b_dstPort_key];
		
		hashV_valid <= metadata_in_valid;
		valid_temp[0] <= hashV_valid;
		valid_temp[1] <= valid_temp[0];
	end
end

/*************************************************************************************/
/**	this state machine is used to generate conn_index according to the results
*		returned from hash table; 

*	-Knock Knock!
*	-Who's there?
*	-Bu
*	-Bu who?
*	-Bugs...
*	-I hate you, get out of my code!
*/
always @ (posedge clk or negedge reset) begin
	if(!reset) begin
		flowK_idx_valid <= 1'b0;
		flowK_idx_info <= {w_flowKIdx_info{1'b0}};
	end
	else begin
		/* read ctx_hashTb and compare (with simpified hash key)*/
		if(valid_temp[1] == 1'b1) begin	/** hit: read connTb */
			flowK_idx_valid <= 1'b1;
			if(ctx_hashTb[b_valid_hashTb] == 1'b1) 
				flowK_idx_info <=  ctx_hashTb[b_idx_hashTb+w_idx-1:b_idx_hashTb];
			else  /** miss: set '0'*/
				flowK_idx_info <= {w_flowKIdx_info{1'b0}};
		end
		else begin
			flowK_idx_valid <= 1'b0;
		end
	end
end

endmodule    
