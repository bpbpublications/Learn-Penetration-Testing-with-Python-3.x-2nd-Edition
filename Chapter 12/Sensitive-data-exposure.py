#!/usr/bin/env python3
# Sensitive Data Exposure
# Author Yehia Elghaly

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

SENSITIVE_KEYWORDS = ['password', 'token', 'api_key', 'secret', 'credential', 'xss_r']

class BurpExtender(IBurpExtender, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Sensitive Data in URL Scanner")
        callbacks.registerScannerCheck(self)
        return
    
    def doPassiveScan(self, baseRequestResponse):
        issues = []
        
        # Extract URL from the request
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()

        for keyword in SENSITIVE_KEYWORDS:
            if keyword in url:
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "Sensitive Data in URL detected",
                    "The URL contains a potential sensitive keyword: {}. This may expose sensitive information to malicious users.".format(keyword),
                    "Medium", "Certain"
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
        return "Sensitive data exposure through URLs is a common misconfiguration where application developers unintentionally expose sensitive data, such as credentials, in URLs. This information can be logged in various places and can lead to data breaches."

    def getRemediationBackground(self):
        return "Always avoid placing sensitive data in URLs. Instead, use POST requests or other mechanisms that hide the data from URLs."

    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return "Review the application code and modify it to ensure sensitive data is not included in URLs."

    def getHttpMessages(self):
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService