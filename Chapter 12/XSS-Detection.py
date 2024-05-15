#!/usr/bin/env python3
# Cross Site Scripting Scanner
# Author Yehia Elghaly

from burp import IBurpExtender, IScannerCheck, IScanIssue
from array import array

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Potential XSS Detector")
        callbacks.registerScannerCheck(self)
        return

    def doPassiveScan(self, baseRequestResponse):
        # Initialize an empty list to collect issues
        issues = []
        
        # Convert response to string
        response = baseRequestResponse.getResponse()
        response = self._helpers.bytesToString(response)
        
        # Simple payloads to check for reflection
        payloads = ["<script>alert(44)</script>", "\"<xss>\"", "'<xss>'"]
        
        for payload in payloads:
            if payload in response:
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, [array('i', (response.index(payload), response.index(payload) + len(payload)))])],
                    "Potential Cross-Site Scripting",
                    "The application echoes the value without encoding.",
                    "High"))
                
        if len(issues) == 0:
            return None
        return issues


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail + "<br/><br/><div style='font-size:10px'>Issue created by Potential XSS Detector extension</div>"
        self._severity = severity
        return

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService