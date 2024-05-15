#!/usr/bin/env python3
# Default Credentials/Pages Detection
# Author Yehia Elghaly


from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

DEFAULT_PAGES = ['admin', 'login', 'install.php', 'login.php']
DEFAULT_CREDS = [('admin', 'admin'), ('root', 'root'), ('user', 'password')]

class BurpExtender(IBurpExtender, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Default Pages and Credentials Scanner")
        callbacks.registerScannerCheck(self)
        return
    
    def doPassiveScan(self, baseRequestResponse):
        issues = []
        
        # Extract URL from the request
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()

        for page in DEFAULT_PAGES:
            if url.endswith(page):
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "Potential Default Page Detected",
                    "The URL ends with a potential default page: %s. This may indicate an improperly configured application." % page,
                    "Medium", "Firm"
                ))
                break

        body = self._helpers.bytesToString(baseRequestResponse.getRequest())
        for user, passw in DEFAULT_CREDS:
            if user in body and passw in body:
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "Potential Default Credentials Detected",
                    "Possible default credentials %s/%s found in request." % (user, passw),
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
        return "Default pages and credentials pose a security risk as they can give attackers easy access to an application."

    def getRemediationBackground(self):
        return "Always change default credentials and remove default pages or installation files after setting up any application."

    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return "Review the application configuration and ensure all default pages are removed and credentials are changed."

    def getHttpMessages(self):
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService