package burp;

import java.io.*;
import java.util.*;
import java.util.regex.*;


import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class ImageSizeTest {

	public static final Pattern FILENAME_RE = Pattern.compile("(\\d)+x(\\d+)");
	public static final int OFFSET = 42;

	@Parameters
	public static Collection<Object[]> data() {
		File[] imageFiles = new File("test-images").listFiles();
		final ArrayList<Object[]> images =
			new ArrayList<Object[]>(imageFiles.length);

		for (File imageFile : imageFiles) {
			try {
				RandomAccessFile f = new RandomAccessFile(imageFile, "r");
				int fileSize = (int)f.length();
				final byte[] image = new byte[fileSize + OFFSET];
				f.read(image, OFFSET, fileSize);
				Matcher m = FILENAME_RE.matcher(imageFile.getName());
				if (m.find()) {
					int[] size = { Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)) };
					images.add(new Object[] { size, image });
				}
			} catch (IOException ioe) {
				throw new RuntimeException(ioe);
			}
		}
		return images;
	}

	private final int[] size;
	private final byte[] image;

	public ImageSizeTest(int[] size, byte[] image) {
		this.size = size;
		this.image = image;
	}

	@Test
	public void testGetImageSize() {
		assertArrayEquals(size,
				SimpleImageSizeReader.getImageSize(image, OFFSET, image.length - OFFSET));
	}
}
