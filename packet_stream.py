import pyshark
from queue import Queue
from threading import Event

"""This file handles the streaming of packets into a shared queue"""


def RunPacketStream(capture_limit: int, interface: str, packet_queue: Queue, stop_event: Event):
    try:
        count = 0
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            count += 1
            packet_queue.put(packet)
            if stop_event.is_set() or count > capture_limit:
                break
    
    except Exception as e:
        print(f"Could not begin packet capture: {e}")
        exit

    print("Packet_stream thread exiting gracefully")
