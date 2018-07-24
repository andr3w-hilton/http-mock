package net.logicaltrust;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.model.MockRule;
import net.logicaltrust.persistent.MockAdder;

public class MockContextMenuFactory implements IContextMenuFactory {

	private SimpleLogger logger;
	private IContextMenuInvocation invocation;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private MockAdder mockAdder;
	
	public MockContextMenuFactory(SimpleLogger logger, IBurpExtenderCallbacks callbacks, MockAdder mockAdder) {
		this.logger = logger;
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		this.mockAdder = mockAdder;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		this.invocation = invocation;
		JMenuItem jMenuItem = new JMenuItem("Mock HTTP response");
		jMenuItem.addActionListener(e -> actionPerformed(true, false));
		JMenuItem jMenuItemWithoutQuery = new JMenuItem("Mock HTTP response (URL without query)");
		jMenuItemWithoutQuery.addActionListener(e -> actionPerformed(false, false));
		List<JMenuItem> list = new ArrayList<>();
		list.add(jMenuItem);
		list.add(jMenuItemWithoutQuery);
		if(invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE)
		{
			JMenuItem jMenuItemBranch = new JMenuItem("Mock this branch");
			jMenuItemBranch.addActionListener(e -> actionPerformed(false, true));
			list.add(jMenuItemBranch);
		}
		return list;
	}

	public void actionPerformed(boolean fullURL, boolean doBranch) {
		try {
			IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
			
			if (selectedMessages == null) {
				logger.debug("No selected messages");
				return;
			}
			
			for (IHttpRequestResponse msg : selectedMessages) {
				IRequestInfo analyzedReq = helpers.analyzeRequest(msg.getHttpService(), msg.getRequest());
				URL analyzedURL = analyzedReq.getUrl();
				if(doBranch) {
					for(IHttpRequestResponse msgx : callbacks.getSiteMap(analyzedURL.toExternalForm()))
					{
						if(msgx.getRequest() == null || msgx.getResponse() == null) {
							continue;
						}
						IRequestInfo analyzedReqx = helpers.analyzeRequest(msgx.getHttpService(), msgx.getRequest());
						URL analyzedURLx = analyzedReqx.getUrl();
						addMock(fullURL, msgx, analyzedURLx);
					}
				}
				else {
					addMock(fullURL, msg, analyzedURL);
				}
			}
		} catch (Exception ex) {
			logger.getStderr().println("Cannot mock messages");
			ex.printStackTrace(logger.getStderr());
		}
	}

	void addMock(boolean fullURL, IHttpRequestResponse msg, URL analyzedURL) {
		MockRule mockRule = null;
		if (fullURL) {
			mockRule = MockRule.fromURL(analyzedURL);
		} else {
			mockRule = MockRule.fromURLwithoutQuery(analyzedURL);
		}
		MockEntry mockEntry = new MockEntry(true, mockRule, msg.getResponse());
		mockAdder.addMock(mockEntry);
		logger.debug("Mock added for " + mockRule);
	}
}
