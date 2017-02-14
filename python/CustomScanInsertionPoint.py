from burp import IBurpExtender
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IParameter
import string

class BurpExtender(IBurpExtender, IScannerInsertionPointProvider):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Serialized input scan insertion point")
        
        # register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(self)
        
        return
        
    # 
    # implement IScannerInsertionPointProvider
    #
    
    def getInsertionPoints(self, baseRequestResponse):
        
        # retrieve the data parameter
        dataParameter = self._helpers.getRequestParameter(baseRequestResponse.getRequest(), "data")
        if (dataParameter is None):
            return None
        
        else:
            # if the parameter is present, add a single custom insertion point for it
            return [ InsertionPoint(self._helpers, baseRequestResponse.getRequest(), dataParameter.getValue()) ]
        
# 
# class implementing IScannerInsertionPoint
#

class InsertionPoint(IScannerInsertionPoint):

    def __init__(self, helpers, baseRequest, dataParameter):
        self._helpers = helpers
        self._baseRequest = baseRequest
        
        # URL- and base64-decode the data
        dataParameter = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(dataParameter)))

        # parse the location of the input string within the decoded data
        start = string.find(dataParameter, "input=") + 6
        self._insertionPointPrefix = dataParameter[:start]
        end = string.find(dataParameter, "&", start)
        if (end == -1):
            end = dataParameter.length()
        self._baseValue = dataParameter[start:end]
        self._insertionPointSuffix = dataParameter[end:]
        return
        
    # 
    # implement IScannerInsertionPoint
    #
    
    def getInsertionPointName(self):
        return "Base64-wrapped input"

    def getBaseValue(self):
        return self._baseValue

    def buildRequest(self, payload):
        # build the raw data using the specified payload
        input = self._insertionPointPrefix + self._helpers.bytesToString(payload) + self._insertionPointSuffix;
        
        # Base64- and URL-encode the data
        input = self._helpers.urlEncode(self._helpers.base64Encode(input));
        
        # update the request with the new parameter value
        return self._helpers.updateParameter(self._baseRequest, self._helpers.buildParameter("data", input, IParameter.PARAM_BODY))

    def getPayloadOffsets(self, payload):
        # since the payload is being inserted into a serialized data structure, there aren't any offsets 
        # into the request where the payload literally appears
        return None

    def getInsertionPointType(self):
        return INS_EXTENSION_PROVIDED
            