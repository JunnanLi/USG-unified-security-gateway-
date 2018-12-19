//===============================================================//
//	Module name: firewall for Unified Security Gateway (USG);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/14
//	Function outline: USG_v0.1
//===============================================================//

`timescale 1ns/1ps

module Firewall_action(
	clk,
	reset,

	ruleID_valid,
	ruleID,
	action_valid,
	action,

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
parameter 	LMID = 7,			// lmid;
			w_pkt = 134,		// width of cData;
			w_ruleID = 16,		// width of ruleID;
			w_actionTb = 1,	// width of actionTb; 
			d_actionTb = 3,		// depth of actionTb,  i.e.,  8 actions;
			words_actionTb = 8;	// num of actions;

input								clk;
input								reset;
input								ruleID_valid;
input			[w_ruleID-1:0]		ruleID;
output	reg							action_valid;
output	reg							action;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	reg							cin_ready;
output	reg							cout_data_wr;
output reg		[w_pkt-1:0]			cout_data;
input								cout_ready;


/*************************************************************************************/
/***	varialbe declaration */
/** RAM used to buffer aciton*/
reg				[d_actionTb-1:0]	idx_actionTb_search, idx_actionTb_conf;
reg									rden_actionTb_search, rden_actionTb_conf;
reg									wren_actionTb_conf;
reg									data_actionTb_conf;
wire								ctx_actionTb_search, ctx_actionTb_conf;

/** fifo used to buffer cData*/
reg									rdreq_cdata;
wire								empty_cdata;
wire			[133:0]				q_cdata;

/** temps: */
reg						valid_temp[2:0], hit_temp[2:0];
/** state */
reg				[3:0]				state_conf;
parameter		IDLE_S				= 4'd0,
				READ_FIFO_S		= 4'd1,
				WAIT_RAM_1_S		= 4'd2,
				WAIT_RAM_2_S		= 4'd3,
				READ_RAM_S		= 4'd4,
				WAIT_END			= 4'd5;

/*** subModules */
ram_1_8 action_table (
  .clka(clk),    // input wire clka
  .wea(1'b0),      // input wire [0 : 0] wea
  .addra(idx_actionTb_search),  // input wire [7 : 0] addra
  .dina(1'b0),    // input wire [7 : 0] dina
  .douta(ctx_actionTb_search),  // output wire [7 : 0] douta
  .clkb(clk),    // input wire clkb
  .web(wren_actionTb_conf),      // input wire [0 : 0] web
  .addrb(idx_actionTb_conf),  // input wire [7 : 0] addrb
  .dinb(data_actionTb_conf),    // input wire [7 : 0] dinb
  .doutb(ctx_actionTb_conf)  // output wire [7 : 0] doutb
);

fifo_134_64 cdata_buffer(
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(cin_data),                	// input wire [133 : 0] din
  .wr_en(cin_data_wr),      	// input wire wr_en
  .rd_en(rdreq_cdata),            	// input wire rd_en
  .dout(q_cdata),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_cdata)           	 // output wire empty
  //.data_count()  				// output wire [7 : 0] data_count
);

/*************************************************************************************/
/** read actionTb, i.e., assign idx_acitonTb */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// reset
		rden_actionTb_search <= 1'b0;
		idx_actionTb_search <= {d_actionTb{1'b0}};
		valid_temp[0] <= 1'b0;
		valid_temp[1] <= 1'b0;
		valid_temp[2] <= 1'b0;
	end
	else begin
		if(ruleID_valid == 1'b1) begin
			rden_actionTb_search <= 1'b1;
			idx_actionTb_search <= ruleID[d_actionTb-1:0];
			valid_temp[0] <= 1'b1;
		end
		else begin
			rden_actionTb_search <= 1'b0;
			valid_temp[0] <= 1'b0;
		end
		valid_temp[1] <= valid_temp[0];
		valid_temp[2] <= valid_temp[1];
	end
end

/*************************************************************************************/
/** read actions after two clocks */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// reset
		action_valid <= 1'b0;
		action <= 1'b0;
	end
	else begin
		action_valid <= valid_temp[2];
		if(ctx_actionTb_search == 1'b1) action <= 1'b1;
		else action <= 1'b0;
		//action <= ctx_actionTb_search;
	end
end

/*************************************************************************************/
/** state for configuring actionTb */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		cout_data_wr <= 1'b0;
		cout_data <= 134'b0;
		cin_ready <= 1'b1;
		// intermediate register inilization;
		idx_actionTb_conf <= {w_actionTb{1'b0}};
		wren_actionTb_conf <= 1'b0;
		data_actionTb_conf <= 1'b0;
		rden_actionTb_conf <= 1'b1;
		rdreq_cdata <= 1'b0;
		// state inilizaition;
		state_conf <= IDLE_S;
	end
	else begin
		case(state_conf)
			IDLE_S: begin
				// initialization;
				wren_actionTb_conf <= 1'b0;
				rden_actionTb_conf <= 1'b0;
				cout_data_wr <= 1'b0;
				// fifo is not empty and TCAM is ready;
				if((empty_cdata == 1'b0) && (cout_ready == 1'b1)) begin
					rdreq_cdata <= 1'b1;
					state_conf <= READ_FIFO_S;
				end
				else begin
					rdreq_cdata <= 1'b0;
					state_conf <= IDLE_S;
				end
			end
			READ_FIFO_S: begin
				if(q_cdata[103:96] == LMID) begin
					if(q_cdata[126:124] == 3'b001) begin // read;
						/** read actionTb */
						cout_data <= {q_cdata[133:127], 3'b011, q_cdata[123:112], q_cdata[103:96],
							q_cdata[111:104],q_cdata[95:64], 64'b0}; // save the header of cdata;
						rdreq_cdata <= 1'b0;
						rden_actionTb_conf <= 1'b1;
						idx_actionTb_conf <= q_cdata[71+d_actionTb:72];
						state_conf <= WAIT_RAM_1_S;
					end
					else if((q_cdata[126:124] == 3'b010)&&(q_cdata[66:64] == 3'b0)) begin // write;
						/** output cData */
						cout_data_wr <= 1'b0;
						cout_data <= q_cdata;
						/** conf actionTb */
						idx_actionTb_conf <= q_cdata[71+d_actionTb:72];
						wren_actionTb_conf <= 1'b1;
						data_actionTb_conf <= q_cdata[0];
						state_conf <= WAIT_END;
					end
					else begin
						cout_data_wr <= 1'b0;
						state_conf <= WAIT_END;
					end
				end
				else begin // not equal;
					cout_data_wr <= 1'b1;
					cout_data <= q_cdata;
					state_conf <= WAIT_END;
				end
			end
			WAIT_RAM_1_S: begin
				state_conf <= WAIT_RAM_2_S;
			end
			WAIT_RAM_2_S: begin
				state_conf <= READ_RAM_S;
			end
			READ_RAM_S: begin
				cout_data_wr <= 1'b1;
				if(ctx_actionTb_conf == 1'b1) cout_data[0] <= 1'b1;
				else cout_data[0] <= 1'b0;
				//cout_data[0] <= ctx_actionTb_conf;
				rdreq_cdata <= 1'b1;
				state_conf <= WAIT_END;
			end
			WAIT_END: begin
				wren_actionTb_conf <= 1'b0;
				cout_data <= q_cdata;
				if(q_cdata[133:132] == 2'b10) begin
					rdreq_cdata <= 1'b0;
					state_conf <= IDLE_S;
				end
				else begin
					state_conf <= WAIT_END;
				end
			end
			default: begin
				state_conf <= IDLE_S;
			end
		endcase
	end
end


endmodule    
