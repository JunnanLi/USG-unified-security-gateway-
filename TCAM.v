//===============================================================//
//	Module name: TCAM IP core (just 8 rules);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/15
//	Function outline: USG_v0.1
//===============================================================//

`timescale 1ns/1ps

module TCAM(
	clk,
	reset,

	key_ready,
	key_valid,
	key,
	ruleID_valid,
	ruleID,
	hit,
	s_out_ready,

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
			w_key = 104,		// width of key;
			w_pkt = 134,		// width of cData;
			w_ruleID = 16,		// width of ruleID;
			w_TCAM = 1,		// width of actionTb; 
			d_TCAM = 3,		// depth of actionTb,  i.e.,  8 actions;
			words_TCAM = 8;	// num of TCAM rules;

input								clk;
input								reset;
output	reg							key_ready;
input								key_valid;
input			[w_key-1:0]			key;
output	reg							ruleID_valid;
output	reg		[w_ruleID-1:0]		ruleID;
output	reg							hit;
input								s_out_ready;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	reg							cin_ready;
output	reg							cout_data_wr;
output reg		[w_pkt-1:0]			cout_data;
input								cout_ready;


/*************************************************************************************/
/***	varialbe declaration */
/** fifo used to buffer cData*/
reg									rdreq_cdata;
wire								empty_cdata;
wire			[133:0]				q_cdata;

/** temps: */
reg									valid_temp;
reg				[7:0]				hit_bitmap;
reg				[w_key+w_key:0]	rule[7:0];		// 1bit valid, 104 key and 104 mask;
reg				[32:0]				counter[7:0];	// 1bit tag, used to reset counter;
reg				[32:0]				counter_set[7:0];	// 1bit tag, used to reset counter;

/** state */
reg				[3:0]				state_conf;
parameter		IDLE_S				= 4'd0,
				READ_FIFO_S		= 4'd1,
				WAIT_RAM_1_S		= 4'd2,
				WAIT_RAM_2_S		= 4'd3,
				READ_RAM_S		= 4'd4,
				WAIT_END			= 4'd5;

/*** subModules */
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

integer i, j, k;

/*************************************************************************************/
/** compare 8 rules, and return hitness (bitmap) */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// reset
		hit_bitmap <= 8'b0;
		valid_temp <= 1'b0;
	end
	else begin
		for( i = 0; i < 8; i = i+1) begin
			if((rule[i][w_key+w_key] == 1'b1) && ((rule[i][w_key+w_key-1:w_key]&rule[i][w_key-1:0]) == 
				(key&rule[i][w_key-1:0]) )) hit_bitmap[i] <= 1;
			else hit_bitmap[i] <= 0;
		end
		valid_temp <= key_valid;
	end
end

/*************************************************************************************/
/** output hitness info. after comparing rules */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// reset
		hit <= 1'b0;
		ruleID_valid <= 1'b0;
		ruleID <= {w_ruleID{1'b0}};
		key_ready <= 1'b1;
	end
	else begin
		key_ready <= s_out_ready;
		ruleID_valid <= valid_temp;
		if(hit_bitmap == 8'b0) begin 
			hit <= 1'b0;
			ruleID <= 16'hffff;
		end
		else begin
			hit <= 1'b1;
			if(hit_bitmap[3:0] != 4'b0) begin
				if(hit_bitmap[1:0] != 2'b0) begin
					if(hit_bitmap[0] == 1'b1) ruleID <= 16'd0;
					else ruleID <= 16'd1;
				end
				else begin
					if(hit_bitmap[2] == 1'b1) ruleID <= 16'd2;
					else ruleID <= 16'd3;
				end
			end
			else begin
				if(hit_bitmap[5:4] != 2'b0) begin
					if(hit_bitmap[4] == 1'b1) ruleID <= 16'd4;
					else ruleID <= 16'd5;
				end
				else begin
					if(hit_bitmap[6] == 1'b1) ruleID <= 16'd6;
					else ruleID <= 16'd7;
				end
			end
		end
	end
end

/*************************************************************************************/
/** used to update counter */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// reset
		for( j = 0; j < 8; j = j+1) begin
			counter[j] <= 33'b0;
		end
	end
	else begin
		if((ruleID_valid == 1'b1) && (hit == 1'b1)) begin
			for( j = 0; j < 8; j = j+1) begin
				if(ruleID[2:0] == j) counter[j][31:0] <= counter[j][31:0] + 32'd1;
			end
		end
		else begin
			for( j = 0; j < 8; j = j+1) begin
				if(counter[j][32] != counter_set[j][32]) counter[j] <= counter_set[j];
				else counter[j] <= counter[j];
			end
		end
	end	
end

/*************************************************************************************/
/** state for configuring 8 rules */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		cout_data_wr <= 1'b0;
		cout_data <= 134'b0;
		cin_ready <= 1'b1;
		// intermediate register inilization;
		for( j = 0; j < 8; j = j+1) begin
			rule[j] <= {(1+w_key+w_key){1'b0}};
			counter_set[j] <= 33'b0;
		end
		// state inilizaition;
		state_conf <= IDLE_S;
	end
	else begin
		case(state_conf)
			IDLE_S: begin
				// initialization;
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
						/** read rules and output cData */
						cout_data[133:64] <= {q_cdata[133:127],3'b011,q_cdata[123:112],
							q_cdata[103:96], q_cdata[111:104],q_cdata[95:64]};
						for( j = 0; j <8; j = j+1) begin
							if(q_cdata[74:72] == j) begin
								case(q_cdata[67:64])
									4'd0: begin
										cout_data[63:32] <= 32'b0;
										cout_data[31:0] <= counter[j][31:0];
									end	
									4'd1: begin
										cout_data[63:32] <= rule[j][31:0];
										cout_data[31:0] <= rule[j][w_key+31:w_key];
									end
									4'd2: begin
										cout_data[63:32] <= rule[j][63:32];
										cout_data[31:0] <= rule[j][w_key+63:w_key+32];
									end
									4'd3: begin
										cout_data[63:32] <= rule[j][95:64];
										cout_data[31:0] <= rule[j][w_key+95:w_key+64];
									end
									4'd4: begin
										cout_data[63:32] <= {24'b0,rule[j][103:96]};
										cout_data[31:0] <= {q_cdata[31:9], rule[j][w_key+104:w_key+96]};
									end
									4'd5: cout_data[63:0] <= {32'b0, rule[j][31:0]};
									4'd6: cout_data[63:0] <= {32'b0, rule[j][63:32]};
									4'd7: cout_data[63:0] <= {32'b0, rule[j][95:64]};
									4'd8: cout_data[63:0] <= {32'b0, 24'b0,rule[j][103:96]};
									default: begin
										cout_data[63:0] <= 64'b0;
									end
								endcase
							end
						end
						cout_data_wr <= 1'b1;
						state_conf <= WAIT_END;
					end
					else if(q_cdata[126:124] == 3'b010) begin // write;
						/** conf actionTb */
						for( j = 0; j <8; j = j+1) begin
							if(q_cdata[74:72] == j) begin
								case(q_cdata[67:64])
									4'd0: begin
										counter_set[j][31:0] <= q_cdata[31:0];
										counter_set[j][32] <= ~counter_set[j][32];
									end	
									4'd1: begin
										rule[j][31:0] <= q_cdata[63:32];
										rule[j][w_key+31:w_key] <= q_cdata[31:0];
									end
									4'd2: begin
										rule[j][63:32] <= q_cdata[63:32];
										rule[j][w_key+63:w_key+32] <= q_cdata[31:0];
									end
									4'd3: begin
										rule[j][95:64] <= q_cdata[63:32];
										rule[j][w_key+95:w_key+64] <= q_cdata[31:0];
									end
									4'd4: begin
										rule[j][103:96] <= q_cdata[39:32];
										rule[j][w_key+104:w_key+96] <= q_cdata[8:0];
									end
									4'd5: rule[j][31:0] <= q_cdata[31:0];
									4'd6: rule[j][63:32] <= q_cdata[31:0];
									4'd7: rule[j][95:64] <= q_cdata[31:0];
									4'd8: rule[j][103:96] <= q_cdata[7:0];
									default: begin
									end
								endcase
							end
						end
						state_conf <= WAIT_END;
					end
					else begin // process as a read responce?; TO DO...;
						state_conf <= WAIT_END;
					end
				end
				else begin // not equal; just output ;
					cout_data_wr <= 1'b1;
					cout_data <= q_cdata;
					state_conf <= WAIT_END;
				end
			end
			WAIT_END: begin
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
