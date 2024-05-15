#!/usr/bin/env python3
# Open Redirect Detection
# Author Yehia Elghaly


from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Active Open Redirect Detector")
        callbacks.registerScannerCheck(self)
        return

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Create a payload that tries to redirect to example.com
        payload = "http://google.com"
        checkRequest = insertionPoint.buildRequest(payload)
        checkResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest)
        
        # If we get a redirect response and it directs to our payload (i.e., example.com), we likely have an open redirect
        redirectResponse = self._helpers.analyzeResponse(checkResponse.getResponse())
        if 300 <= redirectResponse.getStatusCode() <= 399:
            headers = redirectResponse.getHeaders()
            for header in headers:
                if "Location: http://google.com" in header:
                    return [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [checkResponse],
                        "Open Redirect Detected",
                        "The application seems to be vulnerable to an open redirect via the payload: %s" % payload,
                        "Medium", "Certain"
                    )]
        return []

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0  # Custom issue type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return "Open redirects allow attackers to redirect users from a trusted site to any URL of the attacker's choosing. This can be used in phishing campaigns and other malicious activities."

    def getRemediationBackground(self):
        return "The application should validate and whitelist URLs before redirecting users."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Ensure that only valid, whitelisted URLs are allowed for redirection."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService