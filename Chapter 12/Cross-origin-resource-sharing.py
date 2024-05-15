#!/usr/bin/env python3
# Detect Cross-Origin-Resource-Sharing
# Author Yehia Elghaly

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Custom CORS Scanner")
        callbacks.registerScannerCheck(self)
        return

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        
        # Parse the response headers
        response_info = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        headers = response_info.getHeaders()
        
        for header in headers:
            if "Access-Control-Allow-Origin: *" in header:
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "Misconfigured CORS header detected",
                    "The server has set 'Access-Control-Allow-Origin' to '*', allowing any origin to access the resource.",
                    "High", "Firm"
                ))
                break
                
        return issues

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
        return 0  # Not defined in any category

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService