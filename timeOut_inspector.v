//=====================================================================//
//	Module name: connection time-out inspector of UniMan;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/13(Singles' Day is time out, and triggers the event
//		of waiting for the next Singles' Day. ^-^)
//	Function outline: UniMan_v1.0
//=====================================================================//

`timescale 1ns/1ps
//`define TEST

/*	function description:
*	1) check the connection's last timestamp;
*	2) send agingInfo ot build-in event generator if the connection is
*		out time;
*/

module connection_outTime_inspector(
reset,
clk,
idx_agingTb,
data_agingTb,
rdValid_agingTb,
wrValid_agingTb,
ctx_agingTb,
agingInfo_valid,
agingInfo,
cur_timestamp
);

/*	width or depth or words info of signals
*/
parameter 	w_agingInfo = 16,			// width of aging info to build-in event generator;
			w_agingTb = 17,				// width of aging table;
			d_agingTb = 3,				// depth of aging table;
			w_timestamp = 16,			// width of timestamp;
			/* bit(loaction) of each component in x(table/reg) */
			b_valid_agingTb = 16, 		// last bit of valid in aging table;
			b_ts_agingTb = 0,			// last bit of timestamp in agingTb;
			
			/* constant/static parameter */
			INCREASE_IDX_AGINGTB = 3'd1,// check connetion one by one;
			INTERVAL_AGING = 16'd100;	// one interval is 100ms, so '100' represends 10 seconds;

input							clk;
input							reset;
output	reg	[d_agingTb-1:0]	idx_agingTb;
output	reg	[w_agingTb-1:0]	data_agingTb;
output	reg						rdValid_agingTb;
output	reg						wrValid_agingTb;
input		[w_agingTb-1:0]	ctx_agingTb;
output	reg						agingInfo_valid;
output	reg	[w_agingInfo-1:0]	agingInfo;
input		[w_timestamp-1:0]	cur_timestamp;

/*************************************************************************************/
/*	varialbe declaration */
/* gen agingInfo state machine */


reg	[3:0]	state_aging;	
parameter	IDLE_S				= 4'd0,
			WAIT_RAM_1_S		= 4'd1,
			WAIT_RAM_2_S		= 4'd2,
			READ_AGINGTB_S	= 4'd3;

/*************************************************************************************/
/*	state machine declaration
*	this state machine is used to read agingTb; 
*
*	Learning makes me happy, except reading this stupid code.
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		idx_agingTb <= {d_agingTb{1'b0}};
		rdValid_agingTb <= 1'b0;
		wrValid_agingTb <= 1'b0;
		data_agingTb <= {w_agingTb{1'b0}};
		agingInfo_valid <= 1'b0;
		agingInfo <= {w_agingInfo{1'b0}};
		
		state_aging <= IDLE_S;
	end
	else begin
		case(state_aging)
			IDLE_S: begin
				wrValid_agingTb <= 1'b0;
				agingInfo_valid <= 1'b0;
				/** initialization, start from index of '1', because '0' is empty */
				if(idx_agingTb == {d_agingTb{1'b1}})
					idx_agingTb <= INCREASE_IDX_AGINGTB;
				else
					idx_agingTb <= idx_agingTb + INCREASE_IDX_AGINGTB;
				rdValid_agingTb <= 1'b1;
				state_aging <= WAIT_RAM_1_S;
			end
			WAIT_RAM_1_S: begin
				rdValid_agingTb <= 1'b0;
				state_aging <= WAIT_RAM_2_S;
			end
			WAIT_RAM_2_S: begin
				state_aging <= READ_AGINGTB_S;
			end
			READ_AGINGTB_S: begin
				if(ctx_agingTb[b_valid_agingTb] == 1'b1) begin
					if((ctx_agingTb[w_timestamp-1:0] + INTERVAL_AGING ) == 
						cur_timestamp) 
					begin
						/** out time */
						wrValid_agingTb <= 1'b1;
						data_agingTb <= {w_agingTb{1'b0}};
						agingInfo_valid <= 1'b1;
						agingInfo <= idx_agingTb;
					end
					else begin
						wrValid_agingTb <= 1'b0;
						agingInfo_valid <= 1'b0;
					end
				end
				state_aging <= IDLE_S;
			end
			default: begin
				state_aging <= IDLE_S;
			end
		endcase
	end
end






endmodule    
