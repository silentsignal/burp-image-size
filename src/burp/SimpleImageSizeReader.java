package burp;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SimpleImageSizeReader {
	private static final int MIN_LENGTH = 12;

	public static int[] getImageSize(byte[] image, int offset, int length) {
		if (length < MIN_LENGTH) return null;
		ByteBuffer buf = ByteBuffer.wrap(image, offset, length).order(ByteOrder.BIG_ENDIAN);
		int first32be = buf.getInt();

		if (first32be == 0x89504e47 && // "\x89PNG"
				buf.getInt() == 0x0d0a1a0a) {
			return getPngSize(buf);
		}

		if (first32be == 0x47494638 && // "GIF8"
				((buf.get() - (byte)'7') | 2) == 2 && buf.get() == (byte)'a') {
			buf.order(ByteOrder.LITTLE_ENDIAN);
			return new int[] { buf.getShort(), buf.getShort() };
		}

		if (first32be == 0xffd8ffe0 && // JPEG header
				buf.getInt(offset + 6) == 0x4a464946 && // "JFIF"
				buf.get() == 0) {
			buf.position(offset + buf.getShort(offset + 4) + 4);
			return getJfifSize(buf);
		}

		return null;
	}

	private static int[] getPngSize(ByteBuffer buf) {
		while (buf.remaining() >= 4) {
			int chunkLength = buf.getInt();
			if (chunkLength + 8 > buf.remaining()) return null;
			if (buf.getInt() == 0x49484452) { // "IHDR"
				return new int[] { buf.getInt(), buf.getInt() };
			}
			buf.position(buf.position() + chunkLength);
		}
		return null;
	}

	private static int[] getJfifSize(ByteBuffer buf) {
		while (buf.hasRemaining()) {
			if (buf.get() != (byte)0xff) return null;
			if (buf.get() == (byte)0xc0) {
				int pos = buf.position();
				return new int[] { buf.getShort(pos + 5), buf.getShort(pos + 3) };
			}
			short skip = buf.getShort();
			buf.position(buf.position() + skip - 2);
		}
		return null;
	}
}
