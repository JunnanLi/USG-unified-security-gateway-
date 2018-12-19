//===============================================================//
//	Module name: firewall for Unified Security Gateway (USG);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/14
//	Function outline: USG_v0.1
//===============================================================//

`timescale 1ns/1ps

module lookup_pathID(
	clk,
	reset,

	ruleID_valid,
	ruleID,
	hit,
	pathID_valid,
	pathID,

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
			w_pathTb = 16,		// width of pathTb; 
			d_pathTb = 3,		// depth of pathTb,  i.e.,  8 path;
			words_pathTb = 8;	// num of pathTb entries;

input								clk;
input								reset;
input								ruleID_valid;
input			[w_ruleID-1:0]		ruleID;
input								hit;
output	reg							pathID_valid;
output	reg		[17:0]				pathID;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	reg							cin_ready;
output	reg							cout_data_wr;
output reg		[w_pkt-1:0]			cout_data;
input								cout_ready;


/*************************************************************************************/
/***	varialbe declaration */
/** RAM used to buffer aciton*/
reg				[d_pathTb-1:0]		idx_pathTb_conf;
reg									rden_pathTb_conf;
reg									wren_pathTb_conf;
reg				[w_pathTb-1:0]		data_pathTb_conf;
wire			[w_pathTb-1:0]		ctx_pathTb_search, ctx_pathTb_conf;

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
ram_16_8 pathID_table (
  .clka(clk),    					// input wire clka
  .wea(1'b0),      					// input wire [0 : 0] wea
  .addra(ruleID[d_pathTb-1:0]),  // input wire [7 : 0] addra
  .dina(1'b0),    					// input wire [7 : 0] dina
  .douta(ctx_pathTb_search),  	// output wire [7 : 0] douta
  .clkb(clk),    					// input wire clkb
  .web(wren_pathTb_conf),      	// input wire [0 : 0] web
  .addrb(idx_pathTb_conf),  	// input wire [7 : 0] addrb
  .dinb(data_pathTb_conf),    	// input wire [7 : 0] dinb
  .doutb(ctx_pathTb_conf)  		// output wire [7 : 0] doutb
);

fifo_134_64 cdata_buffer(
  .clk(clk),                			// input wire clk
  .srst(!reset),            			// input wire srst
  .din(cin_data),                		// input wire [133 : 0] din
  .wr_en(cin_data_wr),      	// input wire wr_en
  .rd_en(rdreq_cdata),            	// input wire rd_en
  .dout(q_cdata),              		// output wire [133 : 0] dout
  .full(),              				// output wire full
  .empty(empty_cdata)          	// output wire empty
  //.data_count()  			// output wire [7 : 0] data_count
);

/*************************************************************************************/
/** read actionTb, i.e., assign idx_acitonTb */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// reset
		hit_temp[0] <= 1'b0;  valid_temp[0] <= 1'b0;
		hit_temp[1] <= 1'b0;  valid_temp[1] <= 1'b0;
	end
	else begin
		valid_temp[0] <= ruleID_valid;
		valid_temp[1] <= valid_temp[0];
		hit_temp[0] <= hit;
		hit_temp[1] <= hit_temp[0];
	end
end

/*************************************************************************************/
/** read actions after two clocks */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// reset
		pathID_valid <= 1'b0;
		pathID <= 16'b0;
	end
	else begin
		pathID_valid <= valid_temp[1];
		if(hit_temp[1] == 1'b0) begin
			// just pass; or just drop?
			pathID <= 16'd0;	// path <= 16'd1;
		end
		else begin
			pathID <= ctx_pathTb_search;
		end
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
		idx_pathTb_conf <= {w_pathTb{1'b0}};
		wren_pathTb_conf <= 1'b0;
		data_pathTb_conf <= 1'b0;
		rden_pathTb_conf <= 1'b1;
		rdreq_cdata <= 1'b0;
		// state inilizaition;
		state_conf <= IDLE_S;
	end
	else begin
		case(state_conf)
			IDLE_S: begin
				// initialization;
				wren_pathTb_conf <= 1'b0;
				rden_pathTb_conf <= 1'b0;
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
				if((q_cdata[103:96] == LMID) && (q_cdata[66:64] == 3'd4)) begin
					if(q_cdata[126:124] == 3'b001) begin // read;
						/** read actionTb */
						cout_data <= q_cdata; // save the header of cdata;
						rdreq_cdata <= 1'b0;
						rden_pathTb_conf <= 1'b1;
						idx_pathTb_conf <= q_cdata[71+d_pathTb:72];
						state_conf <= WAIT_RAM_1_S;
					end
					else if(q_cdata[126:124] == 3'b010) begin // write;
						/** output cData */
						cout_data_wr <= 1'b1;
						cout_data <= q_cdata;
						/** conf actionTb */
						idx_pathTb_conf <= q_cdata[71+d_pathTb:72];
						wren_pathTb_conf <= 1'b1;
						data_pathTb_conf <= {q_cdata[31:16]};
						state_conf <= WAIT_END;
					end
					else begin
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
				cout_data[31:16] <= ctx_pathTb_conf[15:0];
				cout_data[15:0] <= 16'b0;
				rdreq_cdata <= 1'b1;
				state_conf <= WAIT_END;
			end
			WAIT_END: begin
				wren_pathTb_conf <= 1'b0;
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
