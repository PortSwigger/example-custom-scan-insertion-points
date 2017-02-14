package burp;

import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerInsertionPointProvider
{
    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Serialized input scan insertion point");
        
        // register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(this);
    }

    //
    // implement IScannerInsertionPointProvider
    //
    
    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
    {
        // retrieve the data parameter
        IParameter dataParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "data");
        if (dataParameter == null)
            return null;
        
        // if the parameter is present, add a single custom insertion point for it
        List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();
        insertionPoints.add(new InsertionPoint(baseRequestResponse.getRequest(), dataParameter.getValue()));
        return insertionPoints;
    }

    //
    // class implementing IScannerInsertionPoint
    //
    private class InsertionPoint implements IScannerInsertionPoint
    {
        private byte[] baseRequest;
        private String insertionPointPrefix;
        private String baseValue;
        private String insertionPointSuffix;

        InsertionPoint(byte[] baseRequest, String dataParameter)
        {
            this.baseRequest = baseRequest;
            
            // URL- and base64-decode the data
            dataParameter = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(dataParameter)));

            // parse the location of the input string within the decoded data
            int start = dataParameter.indexOf("input=") + 6;
            insertionPointPrefix = dataParameter.substring(0, start);
            int end = dataParameter.indexOf("&", start);
            if (end == -1)
                end = dataParameter.length();
            baseValue = dataParameter.substring(start, end);
            insertionPointSuffix = dataParameter.substring(end, dataParameter.length());
        }

        // 
        // implement IScannerInsertionPoint
        //
        
        @Override
        public String getInsertionPointName()
        {
            return "Base64-wrapped input";
        }

        @Override
        public String getBaseValue()
        {
            return baseValue;
        }

        @Override
        public byte[] buildRequest(byte[] payload)
        {
            // build the raw data using the specified payload
            String input = insertionPointPrefix + helpers.bytesToString(payload) + insertionPointSuffix;
            
            // Base64- and URL-encode the data
            input = helpers.urlEncode(helpers.base64Encode(input));
            
            // update the request with the new parameter value
            return helpers.updateParameter(baseRequest, helpers.buildParameter("data", input, IParameter.PARAM_BODY));
        }

        @Override
        public int[] getPayloadOffsets(byte[] payload)
        {
            // since the payload is being inserted into a serialized data structure, there aren't any offsets 
            // into the request where the payload literally appears
            return null;
        }

        @Override
        public byte getInsertionPointType()
        {
            return INS_EXTENSION_PROVIDED;
        }
    }
}