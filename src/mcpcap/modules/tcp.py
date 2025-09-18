"""TCP analysis module."""

from collections import defaultdict
from typing import Any

from fastmcp import FastMCP
from scapy.all import IP, TCP, rdpcap

from .base import BaseModule


class TCPModule(BaseModule):
    """Module for analyzing TCP packets in PCAP files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "TCP"

    def analyze_tcp_packets(self, pcap_file: str) -> dict[str, Any]:
        """
        Analyze TCP packets from a PCAP file and return comprehensive analysis results.

        Args:
            pcap_file: Path to local PCAP file or HTTP URL to remote PCAP file

        Returns:
            A structured dictionary containing TCP packet analysis results
        """
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual TCP packet analysis on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)
            tcp_packets = [pkt for pkt in packets if pkt.haslayer(TCP)]

            if not tcp_packets:
                return {
                    "file": pcap_file,
                    "total_packets": len(packets),
                    "tcp_packets_found": 0,
                    "message": "No TCP packets found in this capture",
                }

            # Apply max_packets limit if specified
            packets_to_analyze = tcp_packets
            limited = False
            if self.config.max_packets and len(tcp_packets) > self.config.max_packets:
                packets_to_analyze = tcp_packets[: self.config.max_packets]
                limited = True

            # Define the state dicts which hold already processed packets.
            # Its internal structure is defined in the function logic.
            dup_ack_state = dict
            retransmission_state = dict

            # Define the "result" dictionary, which holds the result of the `detect_*` functions.
            # Result dictionary structure:
            #
            # results:
            # {
            #    "<detection_name>": list,
            #        # Key: name of the detection (e.g. "duplicate_acks")
            #        # Value: list of packets encountered for this type of detection
            # }
            # The key name ("<detection_name>") is used as return key name in the statistics json field
            packet_details = dict

            for _, pkt in enumerate(packets_to_analyze, 1):
                # packet_info = self._analyze_tcp_packet(pkt, i)

                packet_details["duplicate_ack"].append(
                    self._detect_duplicate_ack(pkt, dup_ack_state)
                )
                packet_details["retransmission"].append(
                    self._detect_retransmission(pkt, retransmission_state)
                )
                packet_details["connection_reset"].append(self._detect_reset(pkt))
                # packet_details.append(packet_info)

            # Generate statistics
            stats = self._generate_statistics(packet_details)

            result = {
                "file": pcap_file,
                "total_packets": len(packets),
#                "tcp_packets_found": len(tcp_packets),
#                "tcp_packets_analyzed": len(packet_details),
                "statistics": stats,
                "packets": packet_details,
            }

            # Add information about packet limiting
            if limited:
                result["note"] = (
                    f"Analysis limited to first {self.config.max_packets} TCP packets due to --max-packets setting"
                )

            return result

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

#    def _analyze_tcp_packet(self, packet, packet_num: int) -> dict[str, Any]:
#        """Analyze a single TCP packet and extract relevant information."""
#        info = {
#            "packet_number": packet_num,
#            "timestamp": packet.time,
#        }
#
#        # TCP analysis
#        if packet.haslayer(TCP):
#            tcp_layer = packet[TCP]
#            tcp_info = self._parse_tcp_options(tcp_layer.options)
#            info.update(tcp_info)
#
#        return info

    def _detect_reset(self, packet) -> Any | None:
        """
        Detect if a packet has the TCP RST bit set.

        Args:
            packet: scapy packet
        Returns:
            packet: the packet if it is RST, None otherwise
        """

        if TCP in packet and packet[TCP].flags & 0x04:  # RST flag set
            return packet
        return None

    def _detect_duplicate_ack(self, packet, state) -> Any | None:
        """
        Detect if packet is a duplicate ACK and add it to the state dict anyway.

        Args:
            packet: Scapy packet object
            state: A dictionary containing already seen ACK packets

        Returns:
            packet: the packet if it's a duplicate ACK, None otherwise

        State dictionary structure:
        {
            "seen_acks": defaultdict(set),
                # Key: flow tuple (src_ip, dst_ip, src_port, dst_port)
                # Value: set of ACK numbers already observed for this flow
            "duplicates": list,
                # List of dicts describing each detected duplicate ACK:
                # {
                #   "flow": (src_ip, dst_ip, src_port, dst_port),
                #   "ack": <ack_number>,
                #   "packet": <scapy summary string>
                # }
        }
        """
        if "seen_acks" not in state:
            state["seen_acks"] = defaultdict(set)
            state["duplicates"] = []

        if TCP in packet and IP in packet:
            tcp = packet[TCP]
            flow = (packet[IP].src, packet[IP].dst, tcp.sport, tcp.dport)

            # only consder "explicit" acks
            if len(tcp.payload) == 0 and tcp.flags == "A":
                if tcp.ack in state["seen_acks"][flow]:
                    return packet
                else:
                    state["seen_acks"][flow].add(tcp.ack)
        return None

    def _detect_retransmission(self, packet, state) -> Any | None:
        """
        Detect retransmissions one packet at a time and update the state dictionary.

        Args:
            packet: Scapy packet object
            state: A dictionary to maintain seen sequence numbers

        State dictionary structure:
        {
            "seen_seqs": defaultdict(set),
                # Key: flow tuple (src_ip, dst_ip, src_port, dst_port)
                # Value: set of (seq, payload_len) tuples observed for this flow
            "retransmissions": list,
                # List of dicts describing each detected retransmission:
                # {
                #   "flow": (src_ip, dst_ip, src_port, dst_port),
                #   "seq": <sequence_number>,
                #   "len": <payload_length>,
                #   "packet": <scapy summary string>
                # }
        }
        """
        if "seen_seqs" not in state:
            state["seen_seqs"] = defaultdict(set)

        if TCP in packet and IP in packet:
            tcp = packet[TCP]
            flow = (packet[IP].src, packet[IP].dst, tcp.sport, tcp.dport)

            seq = tcp.seq
            payload_len = len(tcp.payload)
            key = (seq, payload_len)

            if key in state["seen_seqs"][flow]:
                return packet
            else:
                state["seen_seqs"][flow].add(key)
        return None

    def _detect_port_number_reused(self) -> Any | None:
        pass

    def _generate_statistics(self, packets) -> dict[str, Any]:
        """Generate statistics from analyzed TCP packets."""

        stats = {}

        for key, val in packets.items():
            stats.update({"tcp_" + key: len(val)})

        return stats

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up TCP-specific analysis prompts for the MCP server.

        Args:
            mcp: FastMCP server instance
        """

        @mcp.prompt
        def tcp_network_analysis() -> str:
            """Prompt for analyzing TCP traffic from a network perspective"""
            return """You are a network administrator analyzing TCP traffic. Focus your analysis on:

1. **TCP connection tracking:**
   - Analyze different phases of a TCP connection within a stream
   - Track Duplicate Acks and retransmissions
   - Identify Connection Resets

Provide specific recommendations for network optimization and problem resolution."""
