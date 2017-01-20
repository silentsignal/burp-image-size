package burp;

import java.net.URL;
import java.text.MessageFormat;
import java.util.*;

public class ImageTragickIssue implements IScanIssue {
	private final IHttpRequestResponse[] httpMessages;
	private final URL url;
	private final String name, host;
	private final long baseTime, sleepTime;
	private final List<IBurpCollaboratorInteraction> events;

	private static final String ISSUE_NAME = "ImageTragick (CVE-2016-3714)";
	private static final String ISSUE_DETAIL_TIMING =
		"The time it takes for the HTTP response to arrive is <b>{1} ms</b> in case of the " +
		"original request. However, if parameter <b>{0}</b> is replaced by an " + ISSUE_NAME + " " +
		"proof-of-concept that contains a command for a " + BurpExtender.IMAGETRAGICK_SLEEP_SEC + " " +
		"second(s) delay, it takes <b>{2} ms</b>. Based on the difference, the server is " +
		"probably vulnerable to remote code execution caused by " + ISSUE_NAME;
	private static final String ISSUE_DETAIL_COLLABORATOR =
		"The URL <b>http://{1}/a.jpg</b> was included in an MVG formatted " +
		"payload in parameter <b>{0}</b>, and the following interactions " +
		"were recorded by Burp Collaborator: <ul>{2}</ul>" +
		"Based on these interactions, the server is probably " +
		"vulnerable to remote code execution caused by " + ISSUE_NAME;

	private static final String REMEDIATION =
		"Apply the remediations on <a href='https://imagetragick.com/'>https://imagetragick.com/</a>";

	private static final String BACKGROUND =
		"<p>There are multiple vulnerabilities in <a href='https://www.imagemagick.org/'>" +
		"ImageMagick</a>, a package commonly used by web services to process images. " +
		"One of the vulnerabilities can lead to remote code execution (RCE) if you " +
		"process user submitted images. The exploit for this vulnerability is being " +
		"used in the wild.</p>" +
		"<p>A number of image processing plugins depend on the ImageMagick library, " +
		"including, but not limited to, PHP's imagick, Ruby's rmagick and paperclip, " +
		"and nodejs's imagemagick.</p>";



	private ImageTragickIssue(IHttpRequestResponse baseRequestResponse,
			URL url, String name, long baseTime, long sleepTime,
			String host, List<IBurpCollaboratorInteraction> events) {
		this.httpMessages = new IHttpRequestResponse[] { baseRequestResponse };
		this.url = url;
		this.name = name;
		this.baseTime = baseTime;
		this.sleepTime = sleepTime;
		this.host = host;
		this.events = events;
	}

	public static List<IScanIssue> reportOnTiming(IHttpRequestResponse baseRequestResponse,
			URL url, String name, long baseTime, long sleepTime) {
		return new ImageTragickIssue(baseRequestResponse, url, name, baseTime,
				sleepTime, null, null).wrapIntoSIList();
	}

	public static List<IScanIssue> reportOnCollaborator(IHttpRequestResponse baseRequestResponse,
			URL url, String name, String host, List<IBurpCollaboratorInteraction> events) {
		return new ImageTragickIssue(baseRequestResponse, url, name, -1, -1,
				host, events).wrapIntoSIList();
	}

	private List<IScanIssue> wrapIntoSIList() {
		return Collections.singletonList((IScanIssue)this);
	}

	@Override public String getIssueDetail() {
		if (events == null) {
			return MessageFormat.format(ISSUE_DETAIL_TIMING, name,
					baseTime / 1000000L, sleepTime / 1000000L);
		} else {
			StringBuilder list = new StringBuilder();
			for (IBurpCollaboratorInteraction event : events) {
				list.append("<li>The application made ");
				String type = event.getProperty("type");
				String desc;
				if (type.equalsIgnoreCase("http")) {
					list.append("an <b>HTTP</b> request to");
					desc = "HTTP connection";
				} else if (type.equalsIgnoreCase("dns")) {
					list.append("a <b>DNS</b> lookup of type <b>")
						.append(event.getProperty("query_type")).append("</b> to");
					desc = "DNS lookup";
				} else {
					list.append("an unknown interaction with");
					desc = "interaction";
				}
				list.append(" the Collaborator server using the subdomain <b>")
					.append(event.getProperty("interaction_id")).append("</b>. The ")
					.append(desc).append(" was received from the IP address ")
					.append(event.getProperty("client_ip")).append(" at ")
					.append(event.getProperty("time_stamp")).append(".</li>");
			}
			return MessageFormat.format(ISSUE_DETAIL_COLLABORATOR, name,
					host, list.toString());
		}
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
