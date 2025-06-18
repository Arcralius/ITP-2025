import struct                      # Used to pack integers into binary

MAGIC   = b'DN'                    # 2-byte “magic” header to identify our frame
VERSION = 1                        # Single-byte protocol version

def encode_frame(domain: str, count: int) -> bytes:
    """
    Encode ONE <domain, count> pair into the binary frame:
    [MAGIC][VERSION][DomLen][Domain][Count]
    """
    dom_bytes = domain.encode('utf-8')        # Convert domain to UTF-8 bytes
    dom_len   = len(dom_bytes)                # Compute length of domain

    # Build the frame piece-by-piece.
    #  - '<B'  : little-endian unsigned char  (version)
    #  - '<H'  : little-endian unsigned short (domain length)
    #  - '<I'  : little-endian unsigned int   (count)
    frame  = MAGIC                                     # 2 bytes: 'DN'
    frame += struct.pack('<B', VERSION)                # 1 byte : version
    frame += struct.pack('<H', dom_len)                # 2 bytes: domain length
    frame += dom_bytes                                 # n bytes: domain
    frame += struct.pack('<I', count)                  # 4 bytes: count
    return frame

def flush_counts(counts: dict) -> bytes:
    """
    Concatenate frames for ALL domains in `counts`
    into one payload ready for UDP/TCP send().
    """
    payload = bytearray()                              # Mutable binary buffer
    for dom, cnt in counts.items():                    # Iterate over tally dict
        payload += encode_frame(dom, cnt)              # Append each encoded frame
    return bytes(payload)                              # Return immutable bytes
