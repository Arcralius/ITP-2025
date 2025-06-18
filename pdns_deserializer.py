def decode_datagram(data: bytes):
    """
    Iterate through the concatenated frames inside one datagram
    and yield (domain, count) tuples.
    """
    offset = 0                                         # Cursor into 'data'
    while offset < len(data):
        # --- Header validation ------------------------------------------------
        if data[offset:offset+2] != b'DN':             # Check magic bytes
            raise ValueError("Bad magic at offset", offset)
        version = data[offset+2]                       # Read version (1 byte)
        if version != 1:                               # Simple version gate
            raise ValueError("Unsupported version", version)

        # --- Extract domain length -------------------------------------------
        dom_len = int.from_bytes(data[offset+3:offset+5], 'little')  # 2 bytes
        start   = offset + 5                                         # Domain start
        end     = start  + dom_len                                   # Domain end

        # --- Extract domain string -------------------------------------------
        domain  = data[start:end].decode('utf-8')     # Decode UTF-8 domain

        # --- Extract count ----------------------------------------------------
        count   = int.from_bytes(data[end:end+4], 'little')  # 4-byte count

        # --- Yield or process -------------------------------------------------
        yield domain, count                          # Caller can aggregate/store

        # --- Advance cursor to next frame -------------------------------------
        offset  = end + 4                            # Move past this frame
