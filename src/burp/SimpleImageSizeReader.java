package burp;

import java.util.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class SimpleImageSizeReader {
	private static final int MIN_LENGTH = 12;

	public static int[] getImageSize(byte[] image, int offset, int length) {
		if (length < MIN_LENGTH) return null;
		int first32be = readInt32be(image, offset);

		if (first32be == 0x89504e47 && // "\x89PNG"
				readInt32be(image, offset + 4) == 0x0d0a1a0a) {
			return getPngSize(image, offset + 8, length - 8);
		}

		if (first32be == 0x47494638 && // "GIF8"
				((image[offset + 4] - (byte)'7') | 2) == 2 && image[offset + 5] == (byte)'a') {
			return new int[] { readInt16le(image, offset + 6), readInt16le(image, offset + 8) };
		}

		if (first32be == 0xffd8ffe0 && // JPEG header
				readInt32be(image, offset + 6) == 0x4a464946 && // "JFIF"
				image[offset + 10] == 0) {
			int skip = readInt16be(image, offset + 4) + 4;
			return getJfifSize(new ByteArrayInputStream(image, offset + skip, length - skip));
		}

		return null;
	}

	private static int[] getPngSize(byte[] image, int offset, int length) {
		if (length < 4) return null;
		int chunkLength = readInt32be(image, offset);
		if (chunkLength + 12 > length) return null;
		if (readInt32be(image, offset + 4) == 0x49484452) { // "IHDR"
			return new int[] { readInt32be(image, offset + 8),
					readInt32be(image, offset + 12) };
		} else {
			return getPngSize(image, offset + chunkLength + 12, length - chunkLength - 12);
		}
	}

	private static int[] getJfifSize(final ByteArrayInputStream jfif) {
		try {
			byte[] skip = new byte[2];
			while (jfif.available() > 0) {
				if (jfif.read() != 0xff) return null;
				if (jfif.read() == 0xc0) {
					byte[] payload = new byte[7];
					if (jfif.read(payload) != 7) return null;
					return new int[] { readInt16be(payload, 5), readInt16be(payload, 3) };
				}
				if (jfif.read(skip) != 2) return null;
				jfif.skip(readInt16be(skip, 0) - 2);
			}
		} catch (IOException ioe) { /* returning null is OK for this as well */ }
		return null;
	}

	private static int readInt32be(byte[] source, int offset) {
		return (source[offset] << 24) | ((source[offset + 1] & 0xFF) << 16) |
			((source[offset + 2] & 0xFF) << 8) | (source[offset + 3] & 0xFF);
	}

	private static int readInt16le(byte[] source, int offset) {
		return (source[offset + 1] << 8) | source[offset];
	}

	private static int readInt16be(byte[] source, int offset) {
		return (source[offset] << 8) | (source[offset + 1] & 0xFF);
	}
}
