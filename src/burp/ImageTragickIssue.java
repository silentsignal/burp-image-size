package burp;

import java.net.URL;
import java.text.MessageFormat;

public class ImageTragickIssue implements IScanIssue {
	private final IHttpRequestResponse[] httpMessages;
	private final URL url;
	private final String name;
	private final long baseTime, sleepTime;

	private static final String ISSUE_NAME = "ImageTragick (CVE-2016–3714)";
	private static final String ISSUE_DETAIL =
		"The time it takes for the HTTP response to arrive is <b>{1} ms</b> in case of the " +
		"original request. However, if parameter <b>{0}</b> is replaced by an " + ISSUE_NAME + " " +
		"proof-of-concept that contains a command for a " + BurpExtender.IMAGETRAGICK_SLEEP_SEC + " " +
		"second(s) delay, it takes <b>{2} ms</b>. Based on the difference, the server is " +
		"probably vulnerable to remote code execution caused by " + ISSUE_NAME;

	private static final String REMEDIATION =
		"Apply the remediations on <a href='https://imagetragick.com/'>https://imagetragick.com/</a>";

	private static final String BACKGROUND =
		"<p>There are multiple vulnerabilities in <a href='https://www.imagemagick.org/'>" +
		"ImageMagick</a>, a package commonly used by web services to process images. " +
		"One of the vulnerabilities can lead to remote code execution (RCE) if you " +
		"process user submitted images. The exploit for this vulnerability is being " +
		"used in the wild.</p>" +
		"<p>A number of image processing plugins depend on the ImageMagick library, " +
		"including, but not limited to, PHP’s imagick, Ruby’s rmagick and paperclip, " +
		"and nodejs’s imagemagick.</p>";

	public ImageTragickIssue(IHttpRequestResponse baseRequestResponse,
			URL url, String name, long baseTime, long sleepTime) {
		this.httpMessages = new IHttpRequestResponse[] { baseRequestResponse };
		this.url = url;
		this.name = name;
		this.baseTime = baseTime;
		this.sleepTime = sleepTime;
	}

	@Override public String getIssueDetail() {
		return MessageFormat.format(ISSUE_DETAIL, name,
				baseTime / 1000000L, sleepTime / 1000000L);
	}

	@Override public String getConfidence() { return "Firm"; }
	@Override public IHttpRequestResponse[] getHttpMessages() { return httpMessages; }
	@Override public IHttpService getHttpService() { return httpMessages[0].getHttpService(); }
	@Override public String getIssueBackground() { return BACKGROUND; }
	@Override public String getIssueName() { return ISSUE_NAME; }
	@Override public int getIssueType() { return 0x00100100; }
	@Override public String getRemediationBackground() { return null; }
	@Override public String getRemediationDetail() { return REMEDIATION; }
	@Override public String getSeverity() { return "High"; }
	@Override public URL getUrl() { return url; }
}
