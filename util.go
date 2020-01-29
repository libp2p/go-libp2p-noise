package noise

import "io"

// fillBuffer reads from the given reader until the given buffer
// is full
func fillBuffer(buf []byte, reader io.Reader) (int, error) {
	total := 0
	for total < len(buf) {
		c, err := reader.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += c
	}
	return total, nil
}

// writeAll is a helper that writes to the given io.Writer until all input data
// has been written
func writeAll(writer io.Writer, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		c, err := writer.Write(data[total:])
		if err != nil {
			return total, err
		}
		total += c
	}
	return total, nil
}
