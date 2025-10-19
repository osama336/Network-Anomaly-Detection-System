import streamlit as st
import logging
import pyshark
import netifaces
from threading import Thread
from queue import Queue
from scapy.all import wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP, getmacbyip
from keras.src.saving import load_model
import numpy as np
import pandas as pd
import plotly.express as px
import ipaddress

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class PacketCapture:
    def __init__(self, queue):
        self.cap = None
        self.running = False
        self.queue = queue

    def start_capture(self, packet_count, interface):
        """Start the live packet capture."""
        self.running = True
        self.captured_packets = []  # Store captured packets locally
        try:
            self.cap = pyshark.LiveCapture(interface=interface)
            for packet in self.cap.sniff_continuously(packet_count=packet_count):
                if not self.running:
                    break
                packet_data = {
                    "src": None,
                    "dst": None,
                    "srcport": None,
                    "dstport": None,
                    "protocol": "n/a",
                    "length": packet.length if hasattr(packet, 'length') else 0,
                    "info": "n/a"
                }

                try:
                    if hasattr(packet, "ip"):
                        packet_data["src"] = packet.ip.src
                        packet_data["dst"] = packet.ip.dst
                    if hasattr(packet, "transport_layer"):
                        packet_data["protocol"] = packet.transport_layer

                    # Protocol-specific handling
                    if packet_data["protocol"] == "TCP":
                        packet_data["srcport"] = packet.tcp.srcport
                        packet_data["dstport"] = packet.tcp.dstport
                        packet_data["info"] = f"TCP from {packet_data['srcport']} to {packet_data['dstport']}"
                    elif packet_data["protocol"] == "UDP":
                        packet_data["srcport"] = packet.udp.srcport
                        packet_data["dstport"] = packet.udp.dstport
                        packet_data["info"] = f"UDP from {packet_data['srcport']} to {packet_data['dstport']}"
                    elif 'icmp' in packet:
                        packet_data["protocol"] = "ICMP"
                        icmp_type = int(packet.icmp.type) if hasattr(packet.icmp, 'type') else -1
                        if icmp_type == 8:  # Echo Request
                            packet_data["info"] = "Echo Request"
                        elif icmp_type == 0:  # Echo Reply
                            packet_data["info"] = "Echo Reply"
                        else:
                            packet_data["info"] = f"ICMP Type: {icmp_type}"

                    elif 'ARP' in packet:
                        packet_data.update({
                            "src": packet.arp.src_proto_ipv4,
                            "dst": packet.arp.dst_proto_ipv4,
                            "src_hw": packet.arp.src_hw_mac,  # Source hardware (MAC) address
                            "dst_hw": packet.arp.dst_hw_mac,  # Destination hardware (MAC) address
                            "operation": int(packet.arp.opcode)  # ARP operation (1 for request, 2 for reply)
                        })
                        packet_data["protocol"] = "ARP"
                        packet_data["info"] = f"ARP ({'Request' if packet.arp.opcode == 1 else 'Reply'})"

                    elif "dns" in packet.layers:

                        packet_data["protocol"] = "DNS"

                        # Extract DNS query name if available
                        dns_query = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else 'n/a'

                        # Extract DNS query type if available
                        dns_query_type = packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else 'n/a'

                        # Format the info field with query and query type
                        packet_data["info"] = f"DNS Query: {dns_query}, Type: {dns_query_type}"

                        # Add the extracted details to packet_data
                        packet_data["dns_query"] = dns_query
                        packet_data["dns_query_type"] = dns_query_type

                    elif "HTTP" in packet.layers:
                        packet_data["protocol"] = "HTTP"
                        packet_data["srcport"] = packet.tcp.srcport if hasattr(packet, 'tcp') else 80
                        packet_data["dstport"] = packet.tcp.dstport if hasattr(packet, 'tcp') else 80

                    elif packet.tcp and int(packet.tcp.srcport) == 443 or int(packet.tcp.dstport) == 443:
                        packet_data["protocol"] = "HTTPS"
                        packet_data["srcport"] = packet.tcp.srcport
                        packet_data["dstport"] = packet.tcp.dstport

                    self.captured_packets.append(packet_data)
                    self.queue.put(packet_data)
                except AttributeError:
                    self.queue.put(packet_data)

        finally:
            if self.cap:
                self.cap.close()
            self.running = False


# Load the pre-trained Keras model
@st.cache_resource
def load_keras_model():
    model = load_model("best_model_trained.keras")
    logging.info(f"Model loaded successfully with input shape: {model.input_shape}")
    return model


def ip_to_int(ip):
    """
    Convert an IP address to an integer.
    Handles both IPv4 and IPv6.
    """
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        # Return 0 for invalid IPs
        return 0


def create_ether_layer(ip):
    try:
        mac = getmacbyip(ip)
        if not mac:
            mac = "ff:ff:ff:ff:ff:ff"  # Use broadcast if MAC resolution fails
        return Ether(dst=mac)
    except Exception as e:
        print(f"Error creating Ether layer for IP {ip}: {e}")
        return Ether(dst="ff:ff:ff:ff:ff:ff")


def preprocess_packet(packet):
    """Preprocess a packet to extract features for the model."""
    src_ip = packet.get("src", "0.0.0.0")
    dst_ip = packet.get("dst", "0.0.0.0")
    protocol = packet.get("protocol", "n/a")
    length = int(packet.get("length", 0))

    # Initialize default values for ports
    src_port = 0
    dst_port = 0
    icmp_type = 0
    icmp_code = 0
    icmp_id = 0
    icmp_seq = 0
    arp_op = 0  # Operation code (1 for request, 2 for reply)
    arp_sha = "00:00:00:00:00:00"  # Source hardware address
    arp_tha = "00:00:00:00:00:00"  # Target hardware address
    dns_query = "n/a"  # DNS query name
    dns_query_type = 0  # DNS query type

    if protocol == "TCP" or protocol == "UDP":
        src_port = int(packet.get("srcport", 0)) if packet.get("srcport") else 0
        dst_port = int(packet.get("dstport", 0)) if packet.get("dstport") else 0
    elif protocol == "ICMP":
        icmp_type = int(packet.get("type", 8)) if packet.get("type") else 0
        icmp_code = int(packet.get("code", 0)) if packet.get("code") else 0
        icmp_id = int(packet.get("id", 0)) if packet.get("id") else 0
        icmp_seq = int(packet.get("seq", 0)) if packet.get("seq") else 0

    elif protocol == "HTTP":

        # For HTTP, use default ports if missing
        src_port = int(packet.get("srcport", 80))

        dst_port = int(packet.get("dstport", 80))

    elif protocol == "HTTPS":

        # For HTTPS, use default ports if missing

        src_port = int(packet.get("srcport", 443))

        dst_port = int(packet.get("dstport", 443))

    elif protocol == "DNS":

        # Handle DNS-specific fields

        dns_query = packet.get("qry_name", "n/a")  # Query name

        dns_query_type = int(packet.get("qry_type", 0))  # Query type (e.g., A, AAAA, MX)
    elif protocol == "ARP":
        # Handle ARP-specific fields
        arp_op = int(packet.get("operation", 0)) if packet.get("operation") else 0
        arp_sha = packet.get("src_hw", "00:00:00:00:00:00")  # Source hardware address
        arp_tha = packet.get("dst_hw", "00:00:00:00:00:00")  # Target hardware address
    else:
        # Handle unknown protocols if needed
        pass

    # Convert IP addresses to integers
    src_ip_num = ip_to_int(src_ip)
    dst_ip_num = ip_to_int(dst_ip)

    # Map protocol to numeric representation
    protocol_mapping = {"TCP": 1, "UDP": 2, "ICMP": 3, "DNS": 4, "HTTP": 5, "HTTPS": 6, "ARP": 7, "n/a": 0}
    protocol_num = protocol_mapping.get(protocol, 0)

    # Create feature vector
    input_vector = [src_ip_num, dst_ip_num, src_port, dst_port, protocol_num, length]

    # Optional: Pad feature vector to 16 features if required
    required_length = 16
    if len(input_vector) < required_length:
        input_vector = np.pad(input_vector, (0, required_length - len(input_vector)), mode='constant')

    # Convert to NumPy array and reshape for model input
    input_vector = np.array(input_vector).reshape(1, -1)
    return input_vector


def classify_packet(packet, model):
    """Classify a packet using the loaded Keras model."""
    try:
        input_vector = preprocess_packet(packet)
        predictions = model.predict(input_vector)
        class_index = np.argmax(predictions, axis=1)[0]
        classes = ["benign", "malicious", "outlier"]
        predicted_class = classes[class_index]
        return predicted_class, predictions[0]
    except Exception as e:
        # Log and handle any errors
        logging.error(f"Error in classify_packet: {e}")
        return "error", np.zeros(3)  # Return "error" and a dummy prediction array


def save_packet_individually(packets):
    pass


def export_packets_to_pcap(packets):
    scapy_packets = []
    for idx, packet in enumerate(packets, start=1):
        try:
            # Extract packet fields
            src_ip = packet.get("src", "0.0.0.0")
            dst_ip = packet.get("dst", "0.0.0.0")
            protocol = packet.get("protocol", "IP")
            src_port = int(packet.get("srcport", 0)) if packet.get("srcport") else 0
            dst_port = int(packet.get("dstport", 0)) if packet.get("dstport") else 0
            # Safely get ICMP fields with default values
            icmp_type = int(packet.get("icmp_type", 8)) if packet.get("icmp_type") else 8
            icmp_code = int(packet.get("icmp_code", 0)) if packet.get("icmp_code") else 0
            icmp_id = int(packet.get("icmp_id", 0)) if packet.get("icmp_id") else 0
            icmp_seq = int(packet.get("icmp_seq", 0)) if packet.get("icmp_seq") else 0
            info = packet.get("info", "Generic Packet")  # Default Info
            hwsrc = packet.get("src_hw", "00:00:00:00:00:00")
            hwdst = packet.get("dst_hw", "00:00:00:00:00:00")
            dns_query = packet.get("dns_query", "n/a")
            dns_query_type = int(packet.get("dns_query_type", 1)) if packet.get("dns_query_type") else 1
            arp_op = int(packet.get("operation", 1)) if packet.get("operation") else 1  # 1=Request, 2=Reply
            ttl = int(packet.get("ttl", 64)) if packet.get("ttl") else 64

            # Create IP layer
            ip_layer = IP(src=src_ip, dst=dst_ip, ttl=ttl)

            # Add Info-specific descriptions for each protocol
            if protocol == "TCP":
                info = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                tcp_layer = TCP(sport=src_port, dport=dst_port)
                scapy_packet = Ether() / ip_layer / tcp_layer
            elif protocol == "UDP":
                info = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                udp_layer = UDP(sport=src_port, dport=dst_port)
                scapy_packet = Ether() / ip_layer / udp_layer
            elif protocol == "ICMP":
                # Populate the Info field
                info = f"ICMP {src_ip} -> {dst_ip}, Type={icmp_type}, Code={icmp_code}"
                # Build the ICMP layer
                icmp_layer = ICMP(type=icmp_type, code=icmp_code, id=icmp_id, seq=icmp_seq)
                scapy_packet = Ether() / ip_layer / icmp_layer
            elif protocol == "ARP":
                info = f"ARP {'Request' if arp_op == 1 else 'Reply'} {src_ip} -> {dst_ip}"
                arp_layer = ARP(op=arp_op, hwsrc=hwsrc, hwdst=hwdst, psrc=src_ip, pdst=dst_ip)
                scapy_packet = Ether(src=hwsrc, dst=hwdst) / arp_layer
            elif protocol == "DNS":
                info = f"DNS Query: {dns_query}, Type={dns_query_type}"
                dns_layer = DNS(qd=DNSQR(qname=dns_query, qtype=dns_query_type))
                scapy_packet = Ether() / ip_layer / UDP(sport=src_port, dport=53) / dns_layer
            else:
                info = f"Unknown Protocol {src_ip} -> {dst_ip}"
                scapy_packet = Ether() / ip_layer

            # Append the created packet
            scapy_packets.append(scapy_packet)

            logging.info(f"Packet {idx} processed: {info}")
        except Exception as e:
            logging.error(f"Error processing packet {idx}: {e}")

    # Save the packets to a PCAP file
    try:
        wrpcap("captured_packets.pcap", scapy_packets)
        st.success("Packets exported to 'captured_packets.pcap'.")
    except Exception as e:
        st.error(f"Failed to export packets to PCAP: {e}")


def update_packets_display(model, packet_queue, captured_packets):
    if not packet_queue.empty():
        new_packets = []
        while not packet_queue.empty():
            packet = packet_queue.get()
            packet['timestamp'] = pd.Timestamp.now()
            new_packets.append(packet)

            protocol_mapping = {"TCP": 1, "UDP": 2, "ICMP": 3, "DNS": 4, "HTTP": 5, "ARP": 6, "n/a": 0}
            protocol_num = protocol_mapping.get(packet.get("protocol", "n/a"), 0)
            length = int(packet.get("length", 0))
            try:
                length = int(packet.get("length", 0))
            except ValueError:
                length = 0  # Default to 0 if length is invalid
            packet_features.append([protocol_num, length])

        captured_packets.extend(new_packets)  # Extend the list instead of appending

    if captured_packets:
        st.subheader("Captured Packets:")
        df_packets = pd.DataFrame(captured_packets)  # Create DataFrame for display
        # Add progress bar
        progress_bar = st.progress(0)
        total_packets = len(df_packets)

        try:
            # Classify packets with progress
            for i, packet in enumerate(captured_packets):
                df_packets.loc[i, "detection"] = classify_packet(packet, model)[0]
                progress_bar.progress((i + 1) / total_packets)

            progress_bar.progress(1.0)  # Ensure full progress when done
        except Exception as e:
            st.error(f"Error classifying packets: {e}")
            df_packets["detection"] = "unknown"
        finally:
            progress_bar.empty()  # Remove progress bar

        df_packets['timestamp'] = pd.to_datetime(df_packets['timestamp'], errors='coerce')  # Crucial: Convert to datetime
        st.dataframe(df_packets)
        # Protocol Distribution (Plotly)
        if "protocol" in df_packets.columns:
            protocol_counts = df_packets['protocol'].value_counts()
            fig_protocol = px.pie(
                values=protocol_counts.values,
                names=protocol_counts.index,
                title='Protocol Distribution'
            )
            st.plotly_chart(fig_protocol)
        else:
            st.warning("Protocol data is missing in the captured packets.")

if __name__ == "__main__":
    model = load_keras_model()

    st.title("Network Anomaly Detection System")
    st.write("This application captures and analyzes network packets in real time and detects anomalies.")

    packet_count = st.number_input("Enter the number of packets to capture: min_value=1, max_value=1000", min_value=1,
                                   max_value=1000)

    # Get available network interfaces
    interfaces = netifaces.interfaces()
    st.session_state.setdefault("options", interfaces)


    def update_options():
        # move the selected option to the front of the list if it is not already
        if st.session_state.selected_option != st.session_state.options[0]:
            st.session_state.options.remove(st.session_state.selected_option)
            st.session_state.options.insert(0, st.session_state.selected_option)


    interface = st.selectbox("Network Interfaces:", options=st.session_state.options, key="selected_option",
                             on_change=update_options)
    st.markdown(f'Selected interface: {st.session_state.selected_option}')

    # Initialize session state for capturing
    default_states = {
        'capture_instance': None,
        'capture_thread': None,
        'packet_queue': Queue(),
        'captured_packets': [],
    }
    for key, value in default_states.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Start capture
    if st.button("Start Live Capture"):
        if interface:
            if st.session_state.capture_thread is None or not st.session_state.capture_thread.is_alive():
                st.session_state.packet_queue = Queue()
                st.session_state.captured_packets = []
                st.session_state.capture_instance = PacketCapture(st.session_state.packet_queue)

                st.session_state.capture_thread = Thread(
                    target=st.session_state.capture_instance.start_capture, args=(packet_count, interface)
                )
                st.session_state.capture_thread.start()
                st.success("Live capture started.")
            else:
                st.warning("Capture is already running.")
        else:
            st.error("Please select a network interface.")

    # Process packets from the queue dynamically
    packet_features = []

    # Call the function to update the display
    update_packets_display(model, st.session_state.packet_queue, st.session_state.captured_packets)

    # Visualization packet capture
    if st.button("Visualization packet capture"):
        save_packet_individually(st.session_state.captured_packets)

    # Export captured packets to pcap
    if st.button("Export to PCAP"):
        export_packets_to_pcap(st.session_state.captured_packets)