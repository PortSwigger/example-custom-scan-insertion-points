java_import 'burp.IBurpExtender'
java_import 'burp.IScannerInsertionPointProvider'
java_import 'burp.IScannerInsertionPoint'
java_import 'burp.IParameter'

class BurpExtender
  include IBurpExtender, IScannerInsertionPointProvider

  #
  # implement IBurpExtender
  #

  def	registerExtenderCallbacks(callbacks)
    # obtain an extension helpers object
    @helpers = callbacks.getHelpers

    # set our extension name
    callbacks.setExtensionName "Serialized input scan insertion point"

    # register ourselves as a scanner insertion point provider
    callbacks.registerScannerInsertionPointProvider self

    return
  end

  #
  # implement IScannerInsertionPointProvider
  #

  def getInsertionPoints(baseRequestResponse)
    # retrieve the data parameter
    dataParameter = @helpers.getRequestParameter baseRequestResponse.getRequest, "data"
    return if dataParameter.nil?

    # if the parameter is present, add a single custom insertion point for it
    return [InsertionPoint.new(@helpers, baseRequestResponse.getRequest, dataParameter.getValue)]
  end
end

#
# class implementing IScannerInsertionPoint
#

class InsertionPoint
  include IScannerInsertionPoint

  def initialize(helpers, baseRequest, dataParameter)
    @helpers = helpers
    @baseRequest = baseRequest

    # URL- and base64-decode the data
    dataParameter = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(dataParameter)))

    # parse the location of the input string within the decoded data
    start = dataParameter.index("input=") + 6
    @insertionPointPrefix = dataParameter[0...start]
    end_ = dataParameter.index("&", start)
    end_ = dataParameter.length if end_ == -1
    @baseValue = dataParameter[start...end_]
    @insertionPointSuffix = dataParameter[end_..-1]
    return
  end

  #
  # implement IScannerInsertionPoint
  #

  def getInsertionPointName()
    "Base64-wrapped input"
  end

  def getBaseValue()
    @baseValue
  end

  def buildRequest(payload)
    # build the raw data using the specified payload
    input = @insertionPointPrefix + @helpers.bytesToString(payload) + @insertionPointSuffix

    # Base64- and URL-encode the data
    input = @helpers.urlEncode @helpers.base64Encode(input)

    # update the request with the new parameter value
    return @helpers.updateParameter(@baseRequest, @helpers.buildParameter("data", input, IParameter.PARAM_BODY))
  end

  def getPayloadOffsets(payload)
    # since the payload is being inserted into a serialized data structure, there aren't any offsets
    # into the request where the payload literally appears
  end

  def getInsertionPointType()
    INS_EXTENSION_PROVIDED
  end
end
