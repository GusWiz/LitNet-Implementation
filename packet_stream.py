import pyshark
from queue import Queue
from threading import Event
from loguru import logger

"""This file handles the streaming of packets into a shared queue"""


def RunPacketStream(capture_limit: int, interface: str, packet_queue: Queue, stop_event: Event):
    try:
        count = 0
        logger.info(f"Starting live capture on interface: {interface}")
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            count += 1
            packet_queue.put(packet)
            if stop_event.is_set() or count > capture_limit:
                logger.info("Stop event received, closing capture thread.")
                break
    
    except Exception as e:
        logger.exception(f"Packet capture error: {e}")
        exit

    logger.info("Packet_stream thread exiting gracefully")