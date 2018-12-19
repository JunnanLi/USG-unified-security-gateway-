//===============================================================//
//	Module name: L4Parser module for Unified Security Gateway (USG);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/14 (I need a parser to parse the mind of others)
//	Function outline: USG_v2.0 (i.e., based on sPipe architecture)
//===============================================================//

`timescale 1ns/1ps

/***funciton description:
*		data processing:
*			1) identify Ethernet, IPv4, TCP, UDP, ICMP, HTTP protocol;
*			2) extract 5-tuple, TCP info., HTTP header;
*		control signal processing:
*			1) without any processing;
*/

module L4_Parser(
	clk,
	reset,

	pktin_data_wr,
	pktin_data,
	pktin_ready,
	pktout_data_wr,
	pktout_data,
	pktout_ready
);
/***	width or depth or words info. of signals*/
parameter 	LMID = 0,				// local module ID;
			w_pkt = 134,			// the width of packet if FAST2.0;
			w_5tuple = 104;			// the width of fiveTuple, i.e., protocol, srcPort, dstPort, srcIP, dstIP;

input								clk;
input								reset;
input								pktin_data_wr;
input			[w_pkt-1:0]			pktin_data;
output	reg							pktin_ready;
output	reg							pktout_data_wr;	
output	reg		[w_pkt-1:0]			pktout_data;
input								pktout_ready;

/*************************************************************************************/
/***	varialbe declaration */
/** fields */
reg		[31:0]			src_ip, dst_ip, sendSeq, ackSeq;
reg 		[15:0]			src_port, dst_port, content_length, pkt_length, window;
reg 		[7:0]			protocol, winScale, tcpFlag, pst; // ingressPort, egressPort,
reg 		[3:0]			tcpH_length;

//reg 		[w_pkt-1:0]		fields_temp;

/** temps */
reg 		[w_pkt-1:0]		pkt_temp[5:0], metadata_temp[1:0];
reg 						pkt_valid_temp[5:0];
reg 		[1:0]			pkt_tag; // '1' send metadata_temp[0], '2' send metadata_temp[1];
//reg		[7:0]			pktID;

/*************************************************************************************/
/** state for parsing */
reg 		[3:0]	state_parser;
parameter		IDLE_S					= 4'd0,
				READ_META_1_S		= 4'd1,
				PARSE_ETH_S			= 4'd2,
				PARSE_IP_S			= 4'd3,
				PARSE_TCP_UDP_ICMP_S	= 4'd4,
				PARSE_TCP_S 			= 4'd5,
				WAIT_PKT_TAIL_S		= 4'd6;

integer i;

//assign pktin_ready = pktout_ready;

/*************************************************************************************/
/** metain packet and fields*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		for(i =0; i < 6; i= i+1) begin
			pkt_temp[i] <= {w_pkt{1'b0}};
			pkt_valid_temp[i] <= 1'b0;
		end
		pktin_ready <= 1'b1;
	end
	else begin
		pkt_temp[0] <= pktin_data;
		pkt_valid_temp[0] <= pktin_data_wr;
		for(i = 0; i< 5; i= i +1) begin
			pkt_temp[i+1] <= pkt_temp[i];
			pkt_valid_temp[i+1] <= pkt_valid_temp[i];
		end
		if(pktin_data_wr == 1'b1) pktin_ready <= 1'b0;
		else pktin_ready <= 1'b1;
	end
end

/*************************************************************************************/
/** output packets with modifying metadata*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		pktout_data_wr <= 1'b0;
		pktout_data <= {w_pkt{1'b0}};
		pkt_tag <= 1'b0;
		//pktID <= 8'b0;
	end
	else begin
		//pktout_data_wr <= pkt_valid_temp[5];
		if((pkt_valid_temp[4] == 1'b1)&&(pkt_temp[4][133:132] == 2'b01)) begin
			pktout_data_wr <= 1'b1;
			pkt_tag <= 2'd1;
			pktout_data <= {pkt_temp[4][133:80],pst,pkt_temp[4][71:0]};
			//pktID <= pktID + 8'd1;
		end
		else if(pkt_valid_temp[5] == 1'b1) begin
			pktout_data_wr <= 1'b1;
			if(pkt_tag == 2'd1) begin
				pktout_data <= metadata_temp[0];
				pkt_tag <= 2'd2;
			end
			else if(pkt_tag == 2'd2) begin
				pktout_data <= metadata_temp[1];
				pkt_tag <= 2'd0;
			end
			else begin
				pktout_data <= pkt_temp[5];
			end
		end
		else begin
			pktout_data_wr <= 1'b0;
			pkt_tag <= 2'b0;
		end

		if((pkt_valid_temp[4] == 1'b1)&&(pkt_temp[4][133:132] == 2'b01)) begin
			metadata_temp[0] <= {2'b11,4'b0,24'b0,protocol, src_port, dst_port, src_ip, dst_ip};
		end
		else begin
			metadata_temp[0] <= metadata_temp[0];
		end
		if((pkt_valid_temp[5] == 1'b1)&&(pkt_temp[5][133:132] == 2'b01)) begin
			metadata_temp[1] <= {2'b11,4'b0,content_length, tcpFlag, sendSeq, ackSeq, window, 24'b0};
		end
		else begin
			metadata_temp[1] <= metadata_temp[1];
		end
	end
end



/*************************************************************************************/
/** parse packets, and output packets without modification, so pfv is output later than 
*	the  packet's header, but do not worry that pfv output at the same time with the 
*	next packet;
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// intermediate register inilization;
		{protocol, dst_port, src_port, dst_ip, src_ip, content_length, 
			tcpFlag, sendSeq, ackSeq, window, pst} <= 216'b0;
		pkt_length <= 16'b0;	// length field in IPv4;
		tcpH_length <= 4'b0;	// length field in tcp;
		// fifo initialization;

		// state inilizaition;
		state_parser <= IDLE_S;
	end
	else begin
		case(state_parser)
			IDLE_S: begin
				// initialization;
				{protocol, dst_port, src_port, dst_ip, src_ip, content_length, 
					tcpFlag, sendSeq, ackSeq, window} <= 208'b0;
				pkt_length <= 16'b0;
				tcpH_length <= 4'b0;
				// wait for packet's header;
				if((pktin_data[133:132] == 2'b01)&&(pktin_data_wr == 1'b1)) begin
					state_parser <= READ_META_1_S;
					//rdreq_pktID <= 1'b1;
				end
				else begin
					state_parser <= IDLE_S;
				end
			end
			READ_META_1_S: begin
				state_parser <= PARSE_ETH_S;
				//rdreq_pktID <= 1'b0;
			end
			PARSE_ETH_S: begin
				// the pakcet belongs to IPv4 or not?
				if(pktin_data[31:16] == 16'h0800) state_parser <= PARSE_IP_S;
				else 	state_parser <= WAIT_PKT_TAIL_S; // write pfv in WAIT_PKT_TAIL_S;
			end
			PARSE_IP_S: begin
				// extract srcIP and dstIP's top 16b, and pkt_length;
				{src_ip,dst_ip[31:16]} <= pktin_data[47:0];
				pkt_length <= pktin_data[127:112]; // without length of Ethernet header;
				// the packet belongs to TCP/UDP/ICMP or not, meaningless;
				if((pktin_data[71:64] == 8'h11) || (pktin_data[71:64] == 8'h06) || (pktin_data[71:64] == 8'h1))
					protocol <= pktin_data[71:64];
				else
					protocol <= 8'b0;
				state_parser <= PARSE_TCP_UDP_ICMP_S;
			end
			PARSE_TCP_UDP_ICMP_S: begin
				// extract dstIP's low 16b and srcPort, dstPort;
				if(protocol == 8'h06) begin // TCP;
					{dst_ip[15:0],src_port,dst_port,sendSeq,ackSeq} <= pktin_data[127:16];
					// q_pkt[15:12] is the length of TCP header,  should left-shift 2 bit;
					content_length <= pkt_length - {10'b0,pktin_data[15:12],2'b0} - 16'd20;
					tcpH_length <= pktin_data[15:12];
					tcpFlag <= {2'b0,pktin_data[5:0]};
					state_parser <= PARSE_TCP_S;
				end
				else if(protocol == 8'h11) begin // UDP;
					{dst_ip[15:0],src_port,dst_port} <= pktin_data[127:80];
					state_parser <= WAIT_PKT_TAIL_S;
				end
				else if(protocol == 8'h1) begin // ICMP;
					dst_ip[15:0] <= pktin_data[127:112];
					src_port <= {8'b0,pktin_data[111:104]};
					dst_port <= {8'b0,pktin_data[103:96]};
					state_parser <= WAIT_PKT_TAIL_S;
				end
				else begin // IP packets;
					dst_ip[15:0] <= pktin_data[127:112];
					state_parser <= WAIT_PKT_TAIL_S;
				end
			end
			PARSE_TCP_S: begin
				// extract window, httpType if existing;
				window <= pktin_data[127:112];

				/*** extract httpType just for fixed-length packet;
				if((dst_port == 16'd80) && (tcpH_length == 4'd5) && (content_length > 16'd0)) begin	
					if(pktin_data[79:48] == 24'h474554) // get
						pst <= 8'd1;
					else if(pktin_data[79:48] == 32'h504f5354) // post
						pst <= 8'd2;
					else
						pst <= 8'd0;
				end
				*/
				// extract winScale for SYN packet;
				if((tcpFlag == 8'h02) && (tcpH_length > 4'd5)) begin
					// just for fixed position;
					if(pktin_data[47:24] == 24'h010303)	winScale <= pktin_data[23:16];
					else begin // for any position;
						//TO DO...;
					end
				end
				
				// go back to IDLE_S or not;
				if(pktin_data[133:132] == 2'b10) begin
					state_parser <= IDLE_S;
				end
				else begin
					state_parser <= WAIT_PKT_TAIL_S;
				end
			end
			WAIT_PKT_TAIL_S: begin
				if(pktin_data[133:132] == 2'b10) begin 
				/** packet's tail, do not read fifo anymore, and return back to IDLE_S */
					state_parser <= IDLE_S;
				end
				else begin
					state_parser <= WAIT_PKT_TAIL_S;
				end
			end
			default: begin
				state_parser <= IDLE_S;
			end
		endcase
	end
end



endmodule    
