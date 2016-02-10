package burp;

import java.net.URL;
import java.text.MessageFormat;

public class ImageSizeIssue implements IScanIssue {
	private final IHttpRequestResponse[] httpMessages;
	private final URL url;
	private final IParameter width, height;

	private static final String ISSUE_NAME = "Image size matches request parameters";
	private static final String ISSUE_DETAIL =
		"The size of the image returned in the HTTP response ({0} by {1}) matches exactly " +
		"the values of client-supplied parameters <b>{2}</b> and <b>{3}</b>, respectively. " +
		"This might mean that the server generates an image with dimensions specified by " +
		"the client, which can lead to Denial of Service attacks if no limits are enforced.";

	private static final String REMEDIATION =
		"Limit the dimensions that can be requested as parameters of the request.";

	private static final String BACKGROUND =
		"While resizing images on the fly for generating thumbnails or previews might be " +
		"useful, if the size is specified in parameters controlled by the client, an " +
		"attacker can provide enormous numbers. While the attacker doesn't need to invest " +
		"resources in such an attack, the server might allocate the required pixel buffer " +
		"(resulting in out of memory situations) and/or perform calculations that scale " +
		"with the size of the image (resulting in hogging the server CPU).";

	public ImageSizeIssue(IHttpRequestResponse baseRequestResponse,
			URL url, IParameter width, IParameter height) {
		this.httpMessages = new IHttpRequestResponse[] { baseRequestResponse };
		this.url = url;
		this.width = width;
		this.height = height;
	}

	@Override public String getIssueDetail() {
		return MessageFormat.format(ISSUE_DETAIL, width.getValue(), height.getValue(),
				width.getName(), height.getName());
	}

	@Override public String getConfidence() { return "Firm"; }
	@Override public IHttpRequestResponse[] getHttpMessages() { return httpMessages; }
	@Override public IHttpService getHttpService() { return httpMessages[0].getHttpService(); }
	@Override public String getIssueBackground() { return BACKGROUND; }
	@Override public String getIssueName() { return ISSUE_NAME; }
	@Override public int getIssueType() { return 0x08000000; }
	@Override public String getRemediationBackground() { return null; }
	@Override public String getRemediationDetail() { return REMEDIATION; }
	@Override public String getSeverity() { return "Low"; }
	@Override public URL getUrl() { return url; }
}
